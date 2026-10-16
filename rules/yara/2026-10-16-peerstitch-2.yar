rule peerstitch_staging_scripts {
    meta:
        description = "Detects PEERSTITCH staging and orchestrator JavaScript components used in FortiGate implant deployment"
        author = "Actioner"
        date = "2026-10-16"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        hash_pm = "9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e"
        hash_ipssem = "fc1b10c58057ef9f1f9a1e2a3d4a1c89f43b0ead451398c70ed7a6e0312b36ee"

    strings:
        $s1 = "lldprx" ascii
        $s2 = "ipssem" ascii
        $s3 = "index.wasm" ascii
        $s4 = "/data2/template/" ascii
        $s5 = "killall -9 miglogd" ascii
        $s6 = "killall -9 syslogd" ascii
        $s7 = "diagnose debug crashlog clear" ascii
        $s8 = "../../../../setup" ascii

    condition:
        3 of them
}
