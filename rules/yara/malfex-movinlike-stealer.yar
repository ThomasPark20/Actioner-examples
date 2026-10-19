rule Malware_MALFEX_Movinlike_Stealer
{
    meta:
        description = "Detects the MALFEX movinlike Node.js stealer packed with pkg, via config strings and license key pattern"
        author = "Actioner"
        date = "2026-10-19"
        reference = "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/"
        hash = "8d50cb1ba0c2a16a673a2d08a8fb5c45bd8755c95c30ded98a84c74bfe52c9e6"
        severity = "high"

    strings:
        $license = "MALFEX-" ascii
        $env1 = "NPM_API=" ascii
        $env2 = "NPM_LICENSE=" ascii
        $env3 = "NPM_RAT=" ascii
        $name = "movinlike" ascii fullword
        $c2 = "104.234.65.75" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 100MB and
        (
            (2 of ($env*) and $c2) or
            ($license and $name) or
            ($license and $c2)
        )
}
