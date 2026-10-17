rule Malware_PEERSTITCH_FortiGate_Implant
{
    meta:
        description = "Detects PEERSTITCH ARM64 memory-resident implant targeting FortiGate miglogd and iked daemons via characteristic strings"
        author = "Actioner"
        date = "2026-10-17"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash = "b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $target1 = "/bin/miglogd" ascii
        $target2 = "/bin/iked" ascii
        $marker1 = "169.254.0.1" ascii
        $proc_mem = "/proc/%d/mem" ascii
        $acme_path = "/tmp/apache2/conf/md-acme.conf" ascii
        $acme_decoy = "#0 certs managed by ACME" ascii
        $binary_name = "lldprx" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        4 of them
}
