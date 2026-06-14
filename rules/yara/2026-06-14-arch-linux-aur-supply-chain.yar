rule Malware_AtomicArch_Deps_ELF
{
    meta:
        description = "Detects the Atomic Arch deps ELF payload via characteristic strings from the Rust-compiled infostealer/rootkit binary"
        author = "Actioner"
        date = "2026-06-14"
        reference = "https://ioctl.fail/preliminary-analysis-of-aur-malware/"
        hash = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
        severity = "critical"

    strings:
        $bpf1 = "hidden_pids" ascii
        $bpf2 = "hidden_names" ascii
        $bpf3 = "hidden_inodes" ascii
        $socks1 = "socks greeting write" ascii
        $socks2 = "socks CONNECT write" ascii
        $socks3 = "socks CONNECT failed: rep=" ascii
        $socks4 = "socks5 auth rejected" ascii
        $api1 = "/api/agent" ascii
        $api2 = "/bin/sha256/linux" ascii
        $cap = "CapEff:" ascii
        $machid = "/etc/machine-id" ascii
        $tor1 = "tor-expert-bundle-" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (2 of ($bpf*) and 1 of ($socks*)) or
            (2 of ($socks*) and $api1) or
            ($api1 and $api2 and $tor1) or
            (3 of ($bpf*) and $cap and $machid)
        )
}
