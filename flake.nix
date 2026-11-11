{
  description = "linux-passkey — a TPM 2.0-backed FIDO2/CTAP2 authenticator for Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # OpenSK CTAP2 core, pinned; patched via Nix (no manual clone/patch needed).
    opensk = {
      url = "github:google/OpenSK/af63209d857b93f342a297e7560e78c2b6915497";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, opensk }:
    let
      # x86_64: TPM machines; aarch64: also Apple Silicon (Secure Enclave backend).
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      perSystem = system:
    let
      pkgs = nixpkgs.legacyPackages.${system};

      # Apply our patches to the fetched OpenSK source.
      patchedOpenSK = pkgs.applyPatches {
        name = "opensk-patched";
        src = opensk;
        patches = [
          # Hide pinUvAuthToken without a clientPIN, so browsers use built-in
          # UV and our dialog sees the whole request (account, duplicates).
          ./patches/opensk-pinuvauthtoken.patch
          # Expose ctap::storage so we can spot already-registered sites.
          ./patches/opensk-pub-storage.patch
          # Verify the user on registration too (makeCredUvNotRqd=false).
          ./patches/opensk-uv-on-register.patch
          # Store non-discoverable credentials as discoverable when the
          # TPM-wrapped key does not fit in the fixed-size credential ID.
          ./patches/opensk-resident-fallback.patch
          # Fingerprint outcomes that are not a failed match (Deny, cancel,
          # broken sensor): no UV retry used, and their own status codes.
          ./patches/opensk-uv-outcomes.patch
          # Accept CBOR map keys in any order (sorted on read, duplicates still
          # rejected): Firefox sends getAssertion options as {"uv", "up"}
          # (https://bugzilla.mozilla.org/show_bug.cgi?id=2090860).
          ./patches/opensk-cbor-unordered-keys.patch
          # Ctap::process_command: CTAP2 commands without CTAPHID, for the
          # D-Bus front-end (browser extension).
          ./patches/opensk-process-command.patch
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
        # The browser extension's native messaging host (same binary, picked by
        # name), and its manifests: lib/mozilla/... for Firefox/LibreWolf
        # (home-manager's nativeMessagingHosts), etc/chromium/... for Chromium
        # and Brave.
        postInstall = ''
          ln -s linux-passkey $out/bin/linux-passkey-native-host
          host() {
            mkdir -p "$out/$1"
            cat > "$out/$1/${nativeHostName}.json" <<EOF
          {
            "name": "${nativeHostName}",
            "description": "linux-passkey platform authenticator",
            "path": "$out/bin/linux-passkey-native-host",
            "type": "stdio",
            $2
          }
          EOF
          }
          host lib/mozilla/native-messaging-hosts '"allowed_extensions": ["${geckoId}"]'
          host etc/chromium/native-messaging-hosts '"allowed_origins": ["chrome-extension://${chromiumId}/"]'
        '';
        meta = {
          description = "TPM 2.0-backed FIDO2/CTAP2 authenticator for Linux";
          license = pkgs.lib.licenses.asl20;
          mainProgram = "linux-passkey";
          platforms = pkgs.lib.platforms.linux;
        };
      };
      # The extension's ids (browser/linux-passkey-extension/manifest.json:
      # gecko id, and the Chromium id derived from its "key").
      nativeHostName = "io.github.koxu1996.linux_passkey";
      geckoId = "linux-passkey@koxu1996";
      chromiumId = "gjkneikacpbecbbdppkhijklocpamfoi";

      # The browser extension, one manifest per browser (each without the
      # other's keys): chromium/ (unpacked, for --load-extension) and
      # linux-passkey.xpi (unsigned, for a Firefox/LibreWolf policy install).
      browserExtension = pkgs.runCommand "linux-passkey-browser-extension" {
        nativeBuildInputs = [ pkgs.jq pkgs.zip ];
      } ''
        src=${./browser/linux-passkey-extension}
        mkdir -p $out/chromium firefox
        cp $src/*.js $out/chromium/
        cp $src/*.js firefox/
        jq 'del(.browser_specific_settings) | .background |= del(.scripts)' \
          $src/manifest.json > $out/chromium/manifest.json
        jq 'del(.key) | .background |= del(.service_worker)' \
          $src/manifest.json > firefox/manifest.json
        (cd firefox && zip -qX -r $out/linux-passkey.xpi .)
      '';

      # The approval dialog (agent, GTK4 + libadwaita): its own crate, so the
      # daemon builds without GTK.
      dialog = pkgs.rustPlatform.buildRustPackage {
        pname = "linux-passkey-dialog";
        version = "0.1.0";
        src = ./dialog;
        cargoLock.lockFile = ./dialog/Cargo.lock;
        nativeBuildInputs = [ pkgs.pkg-config pkgs.wrapGAppsHook4 ];
        buildInputs = [ pkgs.gtk4 pkgs.libadwaita ];
        # Adwaita's fingerprint and account icons under hicolor, the fallback
        # every icon theme has, so they show whatever theme the desktop uses.
        postInstall = ''
          icons=$out/share/icons/hicolor/scalable/status
          mkdir -p $icons
          for i in devices/auth-fingerprint-symbolic status/avatar-default-symbolic status/dialog-password-symbolic; do
            cp ${pkgs.adwaita-icon-theme}/share/icons/Adwaita/symbolic/$i.svg $icons/
          done
        '';
        meta = {
          description = "GTK4 approval dialog for linux-passkey";
          license = pkgs.lib.licenses.asl20;
          mainProgram = "linux-passkey-dialog";
          platforms = pkgs.lib.platforms.linux;
        };
      };

      linux-passkey = mkLinuxPasskey { };
      linuxPasskeyTests = (mkLinuxPasskey { pname = "linux-passkey-tests"; }).overrideAttrs { doCheck = true; };
    in
    {
      packages = {
        default = linux-passkey;
        linux-passkey = linux-passkey;
        browser-extension = browserExtension;
        dialog = dialog;
        # With OpenSK's internal debug output (run with RUST_LOG=debug).
        debug = mkLinuxPasskey {
          pname = "linux-passkey-debug";
          features = [ "debug_ctap" ];
        };
      };

      # `nix flake check`: build + unit tests (request parsing, prompts). The
      # tests need no TPM; the package itself skips them (doCheck = false).
      checks.tests = linuxPasskeyTests;

      devShell = pkgs.mkShell {
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
    in
    {
      packages = forAllSystems (system: (perSystem system).packages);
      checks = forAllSystems (system: (perSystem system).checks);
      devShells = forAllSystems (system: { default = (perSystem system).devShell; });

      # NixOS module (systemd user service) — added in nix/module.nix.
      nixosModules.default = import ./nix/module.nix self;
    };
}
