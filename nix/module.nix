self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.linux-passkey;
  pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
in
{
  # Renamed from tpm2-passkey.
  imports = [
    (lib.mkRenamedOptionModule [ "services" "tpm2-passkey" ] [ "services" "linux-passkey" ])
  ];

  options.services.linux-passkey = {
    enable = lib.mkEnableOption "TPM 2.0-backed FIDO2 passkey authenticator";

    user = lib.mkOption {
      type = lib.types.str;
      description = "User to grant TPM/uhid access (added to the tss group).";
    };

    pinentry = lib.mkOption {
      type = lib.types.package;
      default = pkgs.pinentry-qt;
      description = "pinentry package used for the user-presence/verification prompt.";
    };

    pinentryProgram = lib.mkOption {
      type = lib.types.str;
      default = "pinentry-qt";
      description = "pinentry binary name inside the pinentry package.";
    };
  };

  config = lib.mkIf cfg.enable {
    # TPM resource manager (/dev/tpmrm0) + tss group.
    security.tpm2.enable = lib.mkDefault true;
    users.users.${cfg.user}.extraGroups = [ "tss" ];

    # Virtual FIDO HID device + browser access to the created hidraw node.
    boot.kernelModules = [ "uhid" ];
    services.udev.extraRules = ''
      KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="tss", MODE="0660"
    '';

    environment.systemPackages = [ pkg cfg.pinentry ];

    # Runs in the user's graphical session (pinentry needs the display). Inert
    # until /dev/tpmrm0 exists (so it won't crash-loop before PTT is enabled).
    systemd.user.services.linux-passkey = {
      description = "linux-passkey — TPM-backed FIDO2/CTAP2 authenticator";
      wantedBy = [ "graphical-session.target" ];
      after = [ "graphical-session.target" ];
      partOf = [ "graphical-session.target" ];
      unitConfig.ConditionPathExists = "/dev/tpmrm0";
      serviceConfig = {
        ExecStart = "${lib.getExe pkg}";
        Environment = [
          "LINUX_PASSKEY_PINENTRY=${cfg.pinentry}/bin/${cfg.pinentryProgram}"
          "RUST_LOG=info"
        ];
        Restart = "on-failure";
        RestartSec = 3;
      };
    };

    # NOTE: on an impermanence system, add the store dir to /persist so passkeys
    # survive the root rollback, e.g. in persist.nix:
    #   users.andrew.directories = [ ".local/share/linux-passkey" ];
  };
}
