rule UAT10147_SPECTRE_Windows_Implant
{
    meta:
        description = "Detects the SPECTRE Windows implant deployed by UAT-10147 based on distinctive PDB paths, named pipe pattern, and command strings"
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        hash = "008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2"
        severity = "critical"

    strings:
        $pdb1 = "x\xe7\xa5\x9e\xe8\xae\xa2\xe5\x88\xb6\xe5\x85\xa8\xe7\xab\x99\xe5\x8a\xab\xe6\x8c\x81\xe6\x8c\x89\xe6\xb5\x8f\xe8\xa7\x88\xe5\x99\xa8\xe8\xaf\xad\xe8\xa8\x80\xe8\xb7\xb3\xe8\xbd\xac" ascii wide
        $pdb2 = "x\xe7\xa5\x9e\xe7\x9a\x84\xe8\x87\xaa\xe5\xae\x89\xe8\xa3\x85\xe6\x9c\x8d\xe5\x8a\xa1" ascii wide
        $pdb3 = "\\Desktop\\AI\\EfsPotatoCpp\\" ascii
        $pdb4 = "\\Desktop\\AI\\EfsPotatoCPP\\" ascii

        $pipe = "\\\\.\\pipe\\spectre_" ascii wide

        // NOTE: $cmd* strings are encrypted at compile time with xorshift32 PRNG.
        // These will match only in memory dumps or decrypted samples, NOT on-disk binaries.
        $cmd1 = "byovd_load" ascii
        $cmd2 = "byovd_unload" ascii
        $cmd3 = "edr_kill" ascii
        $cmd4 = "hashdump" ascii
        $cmd5 = "chromedump" ascii
        $cmd6 = "steal_token" ascii
        $cmd7 = "earlybird" ascii
        $cmd8 = "execute_assembly" ascii

        $c2_1 = "/api/v1/register" ascii
        $c2_2 = "/api/v1/output" ascii

        $ads = "drivers\\etc\\hosts:cache" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($pdb*) or
            $pipe or
            (3 of ($cmd*)) or
            ($c2_1 and $c2_2 and $ads)
        )
}

rule UAT10147_Specter_Linux_Rootkit
{
    meta:
        description = "Detects the Specter Linux kernel rootkit deployed by UAT-10147 based on distinctive module masquerading and ftrace hooking artifacts"
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"

    strings:
        $mod = "acpi_pad" ascii fullword

        $hook1 = "tcp6_seq_show" ascii fullword
        $hook2 = "tcp4_seq_show" ascii fullword
        $hook3 = "getdents64" ascii fullword

        $cmd1 = "rootkit_load" ascii
        $cmd2 = "rootkit_hide" ascii
        $cmd3 = "rootkit_root" ascii
        $cmd4 = "rootkit_hide_mod" ascii
        $cmd5 = "rootkit_status" ascii
        $cmd6 = "rootkit_persist" ascii
        $cmd7 = "rootkit_unload" ascii

        $svc = "hardware-monitor.service" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 20MB and
        (
            (3 of ($cmd*)) or
            ($mod and 2 of ($hook*)) or
            ($svc and any of ($hook*))
        )
}

rule UAT10147_BadIIS_WebShell
{
    meta:
        description = "Detects UAT-10147 BadIIS/ASHX web shells with distinctive SeoEngineHandler class and X-ID authentication"
        author = "Actioner"
        date = "2026-08-24"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "medium"
        // revision: downgraded from high to medium; standalone $cls (SeoEngineHandler)
        // could match SEO-themed .NET libraries. Require $cls + at least one auth indicator.

    strings:
        $cls = "SeoEngineHandler" ascii wide fullword
        $auth1 = "X-ID" ascii wide
        $auth2 = "x9" ascii wide
        $vn = "\xe8\xb6\x8a\xe5\x8d\x97\xe8\x80\x81\xe9\x80\xbc" // 越南老逼

    condition:
        filesize < 5MB and
        (
            ($cls and any of ($auth*)) or
            ($auth1 and $auth2 and $vn)
        )
}
