self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.linux-passkey;
  pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
  sep = cfg.backend == "sep";
  # The device the backend needs before the service can start.
  hwDevice = if sep then cfg.sepDevice else "/dev/tpmrm0";
in
{
  # Renamed from tpm2-passkey.
  imports = [
    (lib.mkRenamedOptionModule [ "services" "tpm2-passkey" ] [ "services" "linux-passkey" ])
  ];

  options.services.linux-passkey = {
    enable = lib.mkEnableOption "hardware-backed FIDO2 passkey authenticator";

    user = lib.mkOption {
      type = lib.types.str;
      description = "User who runs the authenticator; added to the linux-passkey group (and tss for the TPM).";
    };

    backend = lib.mkOption {
      type = lib.types.enum [ "tpm" "sep" ];
      default = "tpm";
      description = ''
        Hardware behind the passkey keys and the store: `tpm` (TPM 2.0), or
        `sep` (Apple Secure Enclave on Apple Silicon, through the aurora-silicon
        apple_sep driver with its key-ioctls patch, which provides /dev/sep-key).
      '';
    };

    sepDevice = lib.mkOption {
      type = lib.types.str;
      default = "/dev/sep-key";
      description = "Secure Enclave key device (`sep` backend).";
    };

    uv = lib.mkOption {
      type = lib.types.enum [ "pinentry" "fprintd" ];
      default = "pinentry";
      description = ''
        How requests are approved: `pinentry` (a dialog naming the site and
        account), or `fprintd` (that dialog, then a fingerprint check; needs
        services.fprintd with an enrolled finger).
      '';
    };

    pinentry = lib.mkOption {
      type = lib.types.package;
      default = pkgs.pinentry-qt;
      description = "pinentry package used for the approval dialog.";
    };

    pinentryProgram = lib.mkOption {
      type = lib.types.str;
      default = "pinentry-qt";
      description = "pinentry binary name inside the pinentry package.";
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.uv != "fprintd" || config.services.fprintd.enable;
          message = "services.linux-passkey.uv = \"fprintd\" needs services.fprintd.enable";
        }
      ];

      # Access to the virtual FIDO device (and the Secure Enclave key device).
      users.groups.linux-passkey = { };
      users.users.${cfg.user}.extraGroups = [ "linux-passkey" ];

      # Virtual FIDO HID device; browsers get the created hidraw node through
      # systemd's FIDO detection (uaccess).
      boot.kernelModules = [ "uhid" ];
      services.udev.extraRules = ''
        KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="linux-passkey", MODE="0660"
      '' + lib.optionalString sep ''
        KERNEL=="${lib.removePrefix "/dev/" cfg.sepDevice}", SUBSYSTEM=="misc", GROUP="linux-passkey", MODE="0660"
      '';

      environment.systemPackages = [ pkg cfg.pinentry ];

      # Runs in the user's graphical session (the dialog needs the display).
      # Inert until the hardware device exists, so it won't crash-loop.
      systemd.user.services.linux-passkey = {
        description = "linux-passkey — hardware-backed FIDO2/CTAP2 authenticator";
        wantedBy = [ "graphical-session.target" ];
        after = [ "graphical-session.target" ];
        partOf = [ "graphical-session.target" ];
        unitConfig.ConditionPathExists = hwDevice;
        serviceConfig = {
          ExecStart = "${lib.getExe pkg}";
          Environment = [
            "LINUX_PASSKEY_BACKEND=${cfg.backend}"
            "LINUX_PASSKEY_UV=${cfg.uv}"
            "LINUX_PASSKEY_PINENTRY=${cfg.pinentry}/bin/${cfg.pinentryProgram}"
            "RUST_LOG=info"
          ] ++ lib.optional sep "LINUX_PASSKEY_SEP_DEVICE=${cfg.sepDevice}"
            ++ lib.optional (cfg.uv == "fprintd")
            "LINUX_PASSKEY_FPRINTD_VERIFY=${config.services.fprintd.package}/bin/fprintd-verify";
          Restart = "on-failure";
          RestartSec = 3;
        };
      };

      # NOTE: on an impermanence system, add the store dir to /persist so passkeys
      # survive the root rollback, e.g. in persist.nix:
      #   users.andrew.directories = [ ".local/share/linux-passkey" ];
    }

    (lib.mkIf (!sep) {
      # TPM resource manager (/dev/tpmrm0) + tss group.
      security.tpm2.enable = lib.mkDefault true;
      users.users.${cfg.user}.extraGroups = [ "tss" ];
    })
  ]);
}
