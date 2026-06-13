rule Malware_AtomicArch_Infostealer_Deps
{
    meta:
        description = "Detects the Atomic Arch Rust-compiled credential stealer payload (deps binary) via characteristic strings from the AUR supply-chain campaign"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://ioctl.fail/preliminary-analysis-of-aur-malware/"
        hash1 = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
        hash2 = "7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $bpf1 = "hidden_pids" ascii fullword
        $bpf2 = "hidden_names" ascii fullword
        $bpf3 = "hidden_inodes" ascii fullword
        $socks1 = "socks greeting write" ascii
        $socks2 = "socks greeting read" ascii
        $socks3 = "socks CONNECT write" ascii
        $socks4 = "socks5 auth rejected" ascii
        $c2_1 = "/api/agent" ascii
        $c2_2 = "/bin/linux" ascii
        $c2_3 = "/bin/sha256/linux" ascii
        $c2_4 = "server returned empty binary" ascii
        $cred1 = ".vault-token" ascii
        $cred2 = "Local Storage/leveldb" ascii
        $cred3 = "/usr/bin/monero-wallet-gui" ascii
        $cap1 = "CapEff:" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (2 of ($bpf*)) or
            (2 of ($socks*) and 1 of ($c2*)) or
            ($c2_4 and 2 of ($c2*) and 1 of ($cred*)) or
            (3 of ($socks*)) or
            ($cap1 and 3 of ($c2*)) or
            ($cap1 and 2 of ($c2*) and 1 of ($socks*))
        )
}

rule Malware_AtomicArch_ScalesBPF
{
    meta:
        description = "Detects the eBPF rootkit component (scales.bpf.c reference) associated with the Atomic Arch campaign"
        author = "Actioner"
        date = "2026-06-13"
        reference = "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency"
        hash1 = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
        hash2 = "7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $scales = "scales.bpf.c" ascii
        $map1 = "hidden_pids" ascii fullword
        $map2 = "hidden_names" ascii fullword
        $map3 = "hidden_inodes" ascii fullword
        $ptrace1 = "PTRACE_ATTACH" ascii
        $ptrace2 = "PTRACE_SEIZE" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        $scales and 2 of ($map*) and 1 of ($ptrace*)
}
