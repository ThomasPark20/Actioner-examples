rule SPECTRE_Implant_Windows_PDB_Strings
{
    meta:
        description = "Detects SPECTRE implant and associated tooling via PDB debug path strings and development artifacts from UAT-10147"
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        hash = "008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2"

    strings:
        $pdb1 = "x\xe7\xa5\x9e\xe8\xae\xa2\xe5\x88\xb6\xe5\x85\xa8\xe7\xab\x99\xe5\x8a\xab\xe6\x8c\x81" ascii
        $pdb2 = "x\xe7\xa5\x9e\xe7\x9a\x84\xe8\x87\xaa\xe5\xae\x89\xe8\xa3\x85\xe6\x9c\x8d\xe5\x8a\xa1" ascii
        $pdb3 = "EfsPotatoCpp" ascii
        $c2_path1 = "/api/v1/register" ascii
        $c2_path2 = "/api/v1/output" ascii
        $magic_pid = { 69 7A 00 00 }
        $rootkit_mod = "acpi_pad" ascii
        $xid_header = "X-ID" ascii

    condition:
        uint16(0) == 0x5A4D and (
            any of ($pdb*) or
            (all of ($c2_path*) and $xid_header)
        )
        or
        uint32(0) == 0x464C457F and (
            $rootkit_mod and $magic_pid
        )
}

rule SPECTRE_Linux_Rootkit_Specter
{
    meta:
        description = "Detects the Specter Linux kernel rootkit module (acpi_pad.ko) used by SPECTRE implant for process/module hiding and privilege escalation"
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        hash = "1fc83b41d201bfbc4db94e332e0c770be9d74591d9817c1b938ccdf17c7a48a9"

    strings:
        $mod_name = "acpi_pad" ascii
        $ftrace_flag = "FTRACE_OPS_FL_IPMODIFY" ascii
        $hook1 = "hooked_tcp4_seq_show" ascii
        $hook2 = "hooked_tcp6_seq_show" ascii
        $hook3 = "hooked_getdents64" ascii
        $hook4 = "hooked_kill" ascii
        $hook5 = "hooked_tkill" ascii
        $svc_name = "hardware-monitor" ascii

    condition:
        uint32(0) == 0x464C457F and
        $mod_name and
        (
            ($ftrace_flag and 1 of ($hook*)) or
            (2 of ($hook*) and $svc_name)
        )
}

rule SPECTRE_BadIIS_WebShell
{
    meta:
        description = "Detects BadIIS web shell components associated with UAT-10147 SPECTRE campaign, including the dual-layer ASHX loader"
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        hash = "43124b72616ef38b0c8a07b167e971b0e4479626fb5ef2303b2ed993e21f6c4c"

    strings:
        $ashx1 = "CodeDomProvider" ascii wide
        $ashx2 = "X-seo" ascii wide
        $ashx3 = "CompileAssemblyFromSource" ascii wide
        $rev1 = "FromBase64String" ascii wide
        $rev2 = "IHttpHandler" ascii wide
        $fake404 = "404 Not Found" ascii wide

    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0xBBEF or uint16(0) == 0x253C) and
        $ashx2 and 2 of them
}
