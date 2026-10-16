rule peerstitch_fortigate_arm64_implant {
    meta:
        description = "Detects PEERSTITCH ARM64 memory-resident implant targeting FortiGate firewalls via ptrace injection into miglogd and iked"
        author = "Actioner"
        date = "2026-10-16"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash1 = "b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70"
        hash2 = "829b1cd270b30565739a478441833f49f10a49bd06f0d18cc96c8ae4a0431f11"
        hash3 = "bd064244dad748cf2a44074bee56f5bfab4a2b18ee944b75d1b3febd4c1fe02a"

    strings:
        $elf = { 7F 45 4C 46 }
        $mmap_sc = { C8 1B 80 D2 01 00 00 D4 }
        $br_x0 = { 00 00 1F D6 }
        $s_miglogd = "/bin/miglogd" ascii
        $s_iked = "/bin/iked" ascii
        $s_link_local = "169.254.0.1" ascii
        $s_acme_conf = "/tmp/apache2/conf/md-acme.conf" ascii
        $s_acme_managed = "#0 certs managed by ACME" ascii
        $s_proc_mem = "/proc/%d/mem" ascii
        $s_proc_maps = "/proc/%d/maps" ascii
        $s_proc_cmdline = "/proc/%d/cmdline" ascii
        $s_port_marker = "8550" ascii
        $s_ssh_config = "/tmp/upfile/ssh_config" ascii

    condition:
        $elf at 0 and
        (
            ($mmap_sc and $br_x0) or
            (5 of ($s_*)) or
            (1 of ($s_acme_managed, $s_acme_conf, $s_ssh_config) and 3 of ($s_*))
        )
}
