rule SupplyChain_Jscrambler_IntroJS_Container
{
    meta:
        description = "Detects the jscrambler malicious binary container file (dist/intro.js) by its custom CSI magic header and large file size"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86"
        severity = "critical"

    strings:
        $magic = { 1B 43 53 49 01 }

    condition:
        $magic at 0 and filesize > 5MB and filesize < 10MB
}

rule SupplyChain_Jscrambler_SetupJS_Dropper
{
    meta:
        description = "Detects the jscrambler malicious setup.js dropper script that extracts and executes platform-specific binaries from the intro.js container"
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60"
        severity = "critical"

    strings:
        $s1 = "dist/intro.js" ascii
        $s2 = "detached" ascii
        $s3 = "windowsHide" ascii
        $s4 = "unref" ascii
        $s5 = ".exe" ascii
        $s6 = "spawn" ascii
        $s7 = "gunzip" ascii wide nocase
        $s8 = "tmpdir" ascii

    condition:
        filesize < 100KB and 6 of ($s*)
}

rule Malware_Jscrambler_Rust_Infostealer_Linux
{
    meta:
        description = "Detects the Linux ELF payload of the jscrambler Rust infostealer via eBPF dynamic imports and machine fingerprinting paths. Note: $mid* and $rustls/$tor strings may be ChaCha20-Poly1305 encrypted in at-rest binaries; consider memory-scanning deployment for reliable detection."
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd"
        severity = "high"

    strings:
        $elf = { 7F 45 4C 46 }
        $bpf1 = "bpf_object__open_mem" ascii fullword
        $bpf2 = "bpf_object__load" ascii fullword
        $bpf3 = "bpf_program__attach" ascii fullword
        $bpf4 = "bpf_map__fd" ascii fullword
        $libbpf = "libbpf.so.1" ascii
        $mid1 = "/etc/machine-id" ascii
        $mid2 = "/var/lib/dbus/machine-id" ascii
        $mid3 = "/sys/class/dmi/id/board_serial" ascii
        $rustls = "rustls" ascii
        $tor = "check.torproject.org" ascii

    condition:
        $elf at 0 and
        filesize < 20MB and
        (3 of ($bpf*) or $libbpf) and
        1 of ($mid*) and
        ($rustls or $tor)
}

rule Malware_Jscrambler_Rust_Infostealer_Windows
{
    meta:
        description = "Detects the Windows PE payload of the jscrambler Rust infostealer via anti-debug APIs and credential-theft indicators. Note: $cred*, $wallet, $steam, and $sched1 are runtime strings likely encrypted by ChaCha20-Poly1305 in at-rest binaries; consider memory-scanning deployment for reliable detection."
        author = "Actioner"
        date = "2026-07-12"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903"
        severity = "high"

    strings:
        $mz = { 4D 5A }
        $api1 = "IsDebuggerPresent" ascii fullword
        $api2 = "GetExtendedTcpTable" ascii fullword
        $rust = "rustls" ascii
        $sched1 = "schtasks" ascii nocase
        $cred1 = "Login Data" ascii
        $cred2 = "Cookies" ascii
        $wallet = "nngceckbapebfimnlniiiahkandclblb" ascii
        $steam = "steamLoginSecure" ascii

    condition:
        $mz at 0 and
        filesize < 20MB and
        $api1 and $api2 and
        $rust and
        2 of ($cred*, $wallet, $steam, $sched1)
}
