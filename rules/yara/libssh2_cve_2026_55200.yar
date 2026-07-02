rule libssh2_cve_2026_55200_poc_trigger
{
    meta:
        description = "Detects the PoC exploit scaffold for CVE-2026-55200 — a malicious SSH server that triggers the integer overflow in libssh2 ssh2_transport_read() by sending packet_length=0xffffffff with chacha20-poly1305 cipher negotiation."
        author = "Actioner"
        date = "2026-06-30"
        reference = "https://github.com/Fi1ix/exploitarium-06-29/blob/main/libssh2-cve-2026-55200-poc/README.md"
        reference2 = "https://github.com/advisories/GHSA-r8mh-x5qv-7gg2"
        cve = "CVE-2026-55200"
        severity = "critical"

    strings:
        // SSH protocol banner and cipher strings used in the PoC trigger
        $ssh_banner     = "SSH-2.0-" ascii
        $chacha_cipher  = "chacha20-poly1305@openssh.com" ascii
        $curve25519     = "curve25519-sha256" ascii

        // libssh2-specific function and variable names from the vulnerable code path
        $func_name      = "ssh2_transport_read" ascii
        $packet_max     = "LIBSSH2_PACKET_MAXPAYLOAD" ascii

        // PoC repository and exploit identifiers
        $poc_marker1    = "cve-2026-55200" ascii nocase
        $poc_marker2    = "exploitarium" ascii nocase
        $poc_marker3    = "libssh2" ascii nocase

    condition:
        filesize < 5MB and
        (
            // Match PoC source code or documentation referencing the exploit
            ( $poc_marker1 and $poc_marker3 and ($func_name or $packet_max or $chacha_cipher) )
            or
            // Match a compiled PoC binary: SSH banner + chacha cipher + curve25519 kex + exploitarium reference
            ( $ssh_banner and $chacha_cipher and $curve25519 and $poc_marker2 and $poc_marker3 )
        )
}

rule libssh2_vulnerable_binary_version
{
    meta:
        description = "Detects libssh2 shared library or statically linked binary at versions known vulnerable to CVE-2026-55200 (through 1.11.1). Useful for asset inventory and patch verification."
        author = "Actioner"
        date = "2026-06-30"
        reference = "https://github.com/advisories/GHSA-r8mh-x5qv-7gg2"
        cve = "CVE-2026-55200"
        severity = "informational"

    strings:
        $lib_name = "libssh2" ascii

        // Version strings for vulnerable releases
        $ver_1_11_1 = "libssh2/1.11.1" ascii
        $ver_1_11_0 = "libssh2/1.11.0" ascii
        $ver_1_10   = "libssh2/1.10." ascii
        $ver_1_9    = "libssh2/1.9." ascii
        $ver_1_8    = "libssh2/1.8." ascii
        $ver_1_7    = "libssh2/1.7." ascii

        // ELF header magic
        $elf_magic  = { 7F 45 4C 46 }

        // Shared object pattern
        $so_pattern = "libssh2.so" ascii

    condition:
        filesize < 50MB and
        $lib_name and
        any of ($ver_*) and
        ( $elf_magic at 0 or $so_pattern )
}
