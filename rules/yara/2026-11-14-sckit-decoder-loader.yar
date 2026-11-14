rule SCKit_Decoder_Loader
{
    meta:
        description = "Detects the SCKit decoder and Stage0 loader PowerShell scripts that use MachineGuid-based key derivation with PBKDF2-HMAC-SHA256 and AES-256-CBC to unpack the toolkit"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash1 = "338e37f58043635ebab64ee5fdc919935e55cb146ca97834b358f934e55e88ec"
        hash2 = "81cc2baa35b798d6084bd078662fa29ff28df02c46c6ccdb2b43bde97d19f781"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $machine_guid = "MachineGuid" ascii wide
        $x_lab_half = "X-Lab-Half" ascii wide
        $x_lab_salt = "X-Lab-Salt" ascii wide
        $pbkdf2 = "PBKDF2" ascii wide nocase
        $aes = "AES" ascii wide
        $sckit_bundle = "SCKitBundle" ascii wide
        $eadf_php = "EadF.php" ascii wide
        $mo7sen = "mo7sen" ascii wide
        $gzip = "GZip" ascii wide nocase
        $mode_full = "-Mode full" ascii wide

    condition:
        filesize < 2MB and
        (
            ($x_lab_half and $x_lab_salt) or
            ($machine_guid and $pbkdf2 and $aes and ($sckit_bundle or $eadf_php)) or
            ($eadf_php and $mo7sen) or
            ($sckit_bundle and ($gzip or $mode_full)) or
            4 of them
        )
}
