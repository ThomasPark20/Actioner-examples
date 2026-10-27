rule APT_Linux_PEERSTITCH_FortiGate_Implant
{
    meta:
        description = "Detects PEERSTITCH ARM64 injector (lldprx) targeting FortiGate miglogd and iked processes via ptrace-based memory injection"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash = "b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $elf = { 7F 45 4C 46 }
        $arm64 = { 02 00 B7 00 }

        $proc_mem = "/proc/%d/mem" ascii
        $proc_maps = "/proc/%d/maps" ascii
        $proc_cmdline = "/proc/%d/cmdline" ascii
        $miglogd = "/bin/miglogd" ascii
        $iked = "/bin/iked" ascii
        $marker_ip = "169.254.0.1" ascii
        $marker_port = "8550" ascii
        $md_acme = "md-acme.conf" ascii
        $cover_string = "certs managed by ACME" ascii

        $mmap_syscall = { D2 80 1B C0 }
        $nop_instr = { E0 03 00 AA }

    condition:
        $elf at 0 and
        $arm64 at 16 and
        filesize < 5MB and
        (
            ($proc_mem and $miglogd and $iked) or
            (4 of ($proc_mem, $proc_maps, $proc_cmdline, $miglogd, $iked, $marker_ip, $marker_port, $md_acme, $cover_string)) or
            ($mmap_syscall and $nop_instr and 2 of ($proc_mem, $miglogd, $iked))
        )
}

rule APT_Linux_PEERSTITCH_Staging_Scripts
{
    meta:
        description = "Detects PEERSTITCH staging scripts (pM.js, ipssem.js) used in the FortiGate implant delivery chain"
        author = "Actioner"
        date = "2026-10-27"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash = "9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e"
        tlp = "WHITE"
        severity = "high"

    strings:
        $lldprx = "lldprx" ascii fullword
        $data2_template = "/data2/template/" ascii
        $index_wasm = "index.wasm" ascii
        $ipssem = "ipssem.js" ascii
        $setup_traversal = "../../../../setup" ascii
        $md_acme_traversal = "../../tmp/apache2/conf/md-acme.conf" ascii
        $pM = "pM.js" ascii

    condition:
        filesize < 1MB and
        (
            ($setup_traversal or $md_acme_traversal) or
            ($lldprx and $data2_template) or
            (3 of ($lldprx, $data2_template, $index_wasm, $ipssem, $pM))
        )
}
