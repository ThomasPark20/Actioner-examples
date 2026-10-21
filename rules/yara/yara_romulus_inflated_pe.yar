rule ROMULUS_Inflated_PE_LegionLoader_Carrier
{
    meta:
        description = "Detects the inflated PE carrier used in ROMULUS Route B to deliver LegionLoader, characterized by an abnormally large .reloc section exceeding 800 MB used as binary padding to evade scanner file-size limits"
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://www.forescout.com/?p=115732"
        hash = "1f403ac059f172e99968ce96bd0ef1bd1981070b454e3e5d75a71368c3c8762a"
        severity = "high"
        caveat = "This rule may match large PE files that legitimately use Windows CryptoAPI with the Enhanced RSA and AES provider. The filesize > 500MB condition combined with CryptoAPI usage is a behavioral heuristic, not a signature. Treat matches as medium-confidence and triage manually."

    strings:
        $reloc = ".reloc" ascii
        $prov_rsa = "Microsoft Enhanced RSA and AES Cryptographic Provider" ascii wide
        $crypt1 = "CryptAcquireContext" ascii
        $crypt2 = "CryptImportKey" ascii
        $crypt3 = "CryptDecrypt" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize > 500MB and
        $reloc and
        2 of ($crypt*) and
        $prov_rsa
}
