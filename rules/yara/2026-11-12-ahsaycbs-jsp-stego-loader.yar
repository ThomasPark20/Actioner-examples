rule Webshell_AhsayCBS_PNG_Stego_Loader
{
    meta:
        description = "Detects the AhsayCBS.jsp PNG steganography web shell via hardcoded AES key and context attribute"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/ahsaycbs-webshells"
        hash = "6c7a4061bcf08df5fe4a49d37442dc650d751be1a91a8bc802edff213e4d5e61"
        severity = "critical"

    strings:
        $aes_key = "3c6e0b8a9c15224a" ascii
        $attr = "QuCh" ascii
        $lsb = "getRGB" ascii
        $classloader = "ClassLoader" ascii
        $aes = "AES" ascii

    condition:
        filesize < 100KB and
        $aes_key and
        $attr and
        2 of ($lsb, $classloader, $aes)
}
