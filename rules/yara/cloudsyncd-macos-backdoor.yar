rule CloudSyncD_Backdoor_Binary
{
    meta:
        description = "Detects the CloudSyncD second-stage macOS backdoor binary based on embedded strings and characteristics"
        author = "Actioner CTI"
        date = "2026-10-04"
        reference = "https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/"
        reference2 = "https://hackread.com/cloudsyncd-macos-backdoor-fake-zoom-installer-passwords/"

    strings:
        $macho_magic1 = { CA FE BA BE }
        $macho_magic2 = { CF FA ED FE }
        $macho_magic3 = { FE ED FA CF }

        $s1 = "cloudsyncd" ascii
        $s2 = "sync.err" ascii
        $s3 = "cloudsync/.config/logs" ascii
        $s4 = "hw_model" ascii
        $s5 = "cpu_cores" ascii
        $s6 = "machine_name" ascii
        $s7 = "hwid" ascii

        $c2_1 = "jQuery" ascii
        $c2_2 = "task" ascii

        $crypto = "ChaCha20" ascii

    condition:
        ($macho_magic1 at 0 or $macho_magic2 at 0 or $macho_magic3 at 0) and
        3 of ($s*) and
        1 of ($c2*) and
        $crypto
}

rule CloudSyncD_Dropper
{
    meta:
        description = "Detects the CloudSyncD first-stage dropper disguised as a Zoom installer"
        author = "Actioner CTI"
        date = "2026-10-04"
        reference = "https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/"
        reference2 = "https://securityaffairs.com/200293/malware/fake-zoom-installer-hides-macos-backdoor-cloudsyncd.html"

    strings:
        $macho_magic1 = { CA FE BA BE }
        $macho_magic2 = { CF FA ED FE }
        $macho_magic3 = { FE ED FA CF }

        $s1 = "app_installer" ascii
        $s2 = "data.json" ascii
        $s3 = ".config/zoom" ascii
        $s4 = "/dev/fd/" ascii
        $s5 = "mkstemp" ascii
        $s6 = "dscl" ascii

        $unicode1 = { E2 80 8B }
        $unicode2 = { E2 80 8C }

        $swap = ".app_swap_" ascii

    condition:
        ($macho_magic1 at 0 or $macho_magic2 at 0 or $macho_magic3 at 0) and
        3 of ($s*) and
        all of ($unicode*) and
        $swap
}

rule CloudSyncD_ZeroWidth_Unicode_Credential_File
{
    meta:
        description = "Detects the CloudSyncD data.json credential file containing zero-width Unicode character encoding"
        author = "Actioner CTI"
        date = "2026-10-04"
        reference = "https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/"

    strings:
        $json_ver = "\"version\"" ascii
        $json_ver2 = "1.0.0" ascii

        $zwsp = { E2 80 8B }
        $zwnj = { E2 80 8C }

    condition:
        filesize < 10KB and
        $json_ver and $json_ver2 and
        #zwsp > 10 and
        #zwnj > 10
}
