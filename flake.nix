{
  description = "linux-passkey — a TPM 2.0-backed FIDO2/CTAP2 authenticator for Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # OpenSK CTAP2 core, pinned; patched via Nix (no manual clone/patch needed).
    opensk = {
      url = "github:google/OpenSK/a93efdb2a94a01607a8df2813fe06c3f6fb58292";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, opensk }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      # Apply our one-line getInfo patch (pinUvAuthToken only when a PIN is set)
      # to the fetched OpenSK source.
      patchedOpenSK = pkgs.applyPatches {
        name = "opensk-patched";
        src = opensk;
        patches = [
          ./patches/opensk-pinuvauthtoken.patch
          # Expose ctap::storage so we can spot already-registered sites.
          ./patches/opensk-pub-storage.patch
          # Verify the user on registration too (makeCredUvNotRqd=false).
          ./patches/opensk-uv-on-register.patch
          # Store non-discoverable credentials as discoverable when the
          # TPM-wrapped key does not fit in the fixed-size credential ID.
          ./patches/opensk-resident-fallback.patch
        ];
      };

      # Replicate the dev layout (crate + sibling OpenSK) so the Cargo.toml path
      # dependency `../OpenSK/libraries/opensk` resolves in the build sandbox.
      buildTree = pkgs.runCommand "linux-passkey-tree" { } ''
        mkdir -p $out/crate $out/OpenSK
        cp -r ${self}/. $out/crate/
        cp -r ${patchedOpenSK}/. $out/OpenSK/
        chmod -R +w $out
      '';

      mkLinuxPasskey = { pname ? "linux-passkey", features ? [ ] }: pkgs.rustPlatform.buildRustPackage {
        inherit pname;
        buildFeatures = features;
        version = "0.1.0";
        src = buildTree;
        sourceRoot = "linux-passkey-tree/crate";
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [
          pkgs.pkg-config
          pkgs.rustPlatform.bindgenHook # LIBCLANG_PATH for tss-esapi-sys
        ];
        buildInputs = [
          pkgs.tpm2-tss # tss-esapi links this
          pkgs.openssl # opensk build.rs + pkg-config
        ];
        doCheck = false; # OpenSK's tests aren't meaningful here / need a TPM
        meta = {
          description = "TPM 2.0-backed FIDO2/CTAP2 authenticator for Linux";
          license = pkgs.lib.licenses.asl20;
          mainProgram = "linux-passkey";
          platforms = pkgs.lib.platforms.linux;
        };
      };
      linux-passkey = mkLinuxPasskey { };
      linuxPasskeyTests = (mkLinuxPasskey { pname = "linux-passkey-tests"; }).overrideAttrs { doCheck = true; };
    in
    {
      packages.${system} = {
        default = linux-passkey;
        linux-passkey = linux-passkey;
        # With OpenSK's internal debug output (run with RUST_LOG=debug).
        debug = mkLinuxPasskey {
          pname = "linux-passkey-debug";
          features = [ "debug_ctap" ];
        };
      };

      # `nix flake check`: build + unit tests (request parsing, prompts). The
      # tests need no TPM; the package itself skips them (doCheck = false).
      checks.${system}.tests = linuxPasskeyTests;

      # NixOS module (systemd user service) — added in nix/module.nix.
      nixosModules.default = import ./nix/module.nix self;

      devShells.${system}.default = pkgs.mkShell {
        name = "linux-passkey-dev";
        nativeBuildInputs = with pkgs; [
          rustc
          cargo
          rust-analyzer
          clippy
          rustfmt
          pkg-config
          llvmPackages.clang
        ];
        buildInputs = with pkgs; [ tpm2-tss openssl ];
        packages = with pkgs; [ swtpm libtpms tpm2-tools ];
        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        shellHook = ''
          echo "linux-passkey dev shell (rustc $(rustc --version 2>/dev/null | awk '{print $2}'), tpm2-tss ${pkgs.tpm2-tss.version})"
        '';
      };
    };
}
