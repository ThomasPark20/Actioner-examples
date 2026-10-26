rule PHP2Shell_Potassium_Mirai_Variant
{
    meta:
        description = "Detects the Potassium Mirai variant delivered via PHP2Shell exploitation"
        author = "Actioner"
        date = "2026-10-26"
        reference = "https://www.sophos.com/en-us/blog/proof-of-concept-exploit-released-for-php-vulnerabilities-109618-109619"
        hash = "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486"
        severity = "critical"

    strings:
        $c2_domain = "godofthunder" ascii
        $c2_domain2 = "botlesscucks" ascii
        $c2_domain3 = "gettingheadfromduckysmom" ascii
        $elf_magic = { 7F 45 4C 46 }

    condition:
        $elf_magic at 0 and
        (any of ($c2_domain*)) and
        filesize < 5MB
}
