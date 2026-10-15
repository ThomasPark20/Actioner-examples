rule Malware_PEERSTITCH_ARM64_Ptrace_Injector
{
    meta:
        description = "Detects the PEERSTITCH ARM64 ptrace-based process injector targeting FortiGate miglogd/iked daemons, a memory-resident implant used in network appliance exploitation campaigns"
        author = "Actioner"
        date = "2026-10-15"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash = "b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $elf_magic = { 7F 45 4C 46 02 01 01 }

        $s_miglogd = "/bin/miglogd" ascii
        $s_iked = "/bin/iked" ascii
        $s_proc_mem = "/proc/%d/mem" ascii
        $s_proc_maps = "/proc/%d/maps" ascii
        $s_secret = "123456" ascii

        $s_marker1 = "8550" ascii
        $s_marker2 = "169.254.0.1" ascii

        $s_lldprx = "lldprx" ascii
        $s_ipssem = "ipssem" ascii

    condition:
        $elf_magic at 0 and
        filesize < 5MB and
        (
            ($s_miglogd and $s_iked and $s_proc_mem) or
            ($s_proc_mem and $s_proc_maps and 2 of ($s_marker1, $s_marker2, $s_secret)) or
            ($s_lldprx and $s_ipssem and $s_proc_mem)
        )
}

rule Malware_PEERSTITCH_Staging_Script
{
    meta:
        description = "Detects PEERSTITCH staging scripts (pM.js/ipssem.js) used to orchestrate the ptrace injector deployment on FortiGate appliances"
        author = "Actioner"
        date = "2026-10-15"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash = "9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e"
        severity = "high"
        tlp = "WHITE"

    strings:
        $path1 = "/data2/template/" ascii
        $path2 = "../../../../setup" ascii
        $file1 = "lldprx" ascii
        $file2 = "ipssem.js" ascii
        $file3 = "pM.js" ascii
        $file4 = "index.wasm" ascii

    condition:
        filesize < 1MB and
        3 of them
}
