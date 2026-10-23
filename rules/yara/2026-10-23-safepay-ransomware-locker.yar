rule SafePay_Ransomware_Locker
{
    meta:
        description = "SafePay locker: .SafePay extension plus ChaCha constant plus advisory-named locker component"
        author = "Actioner"
        date = "2026-10-23"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a"
        confidence = "low - strings derived from advisory text, not from a detonated sample"

    strings:
        // Advisory: encrypted files receive the .SafePay extension
        $ext = ".SafePay" ascii wide
        // Advisory: ChaCha20 used for file encryption (standard ChaCha sigma constant)
        $chacha = "expand 32-byte k" ascii
        // Advisory Table 3: component file names
        $name1 = "locker.dll" ascii wide nocase
        $name2 = "DYRasWtb" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        $ext and $chacha and 1 of ($name*)
}
