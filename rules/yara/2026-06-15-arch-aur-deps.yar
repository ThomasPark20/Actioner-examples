rule Malware_AtomicArch_Deps_Infostealer
{
    meta:
        description = "Detects the Atomic Arch deps ELF infostealer based on distinctive strings from credential harvesting, eBPF rootkit, and C2 communication"
        author = "Actioner"
        date = "2026-06-15"
        reference = "https://ioctl.fail/preliminary-analysis-of-aur-malware/"
        hash = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $bpf1 = "hidden_pids" ascii
        $bpf2 = "hidden_names" ascii
        $bpf3 = "hidden_inodes" ascii
        $bpf4 = "scales.bpf" ascii

        $c2_1 = "/api/agent" ascii
        $c2_2 = "/upload" ascii
        $c2_3 = "/bin/linux" ascii
        $c2_4 = "/bin/sha256/linux" ascii

        $cred1 = "/.vault-token" ascii
        $cred2 = "/.ssh/" ascii
        $cred3 = "Local Storage/leveldb" ascii
        $cred4 = "Network/Cookies" ascii
        $cred5 = "PuTTY-User-Key-File-" ascii

        $svc1 = "Restart=always" ascii
        $svc2 = "RestartSec=30" ascii

        $miner = "monero-wallet-gui" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (2 of ($bpf*) and 1 of ($c2*)) or
            (3 of ($cred*) and 1 of ($c2*)) or
            (1 of ($bpf*) and 2 of ($cred*) and 1 of ($svc*)) or
            ($miner and 1 of ($bpf*) and 1 of ($c2*))
        )
}
