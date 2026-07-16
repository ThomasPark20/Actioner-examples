rule Malware_OkoBot_SeedHunter
{
    meta:
        description = "Detects OkoBot SeedHunter component targeting hardware cryptocurrency wallet applications via characteristic strings"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://securelist.com/okobot-framework-targets-cryptocurrency-wallets/120660/"
        severity = "critical"

    strings:
        $hook1 = "mal_LogConsoleMessage" ascii wide
        $marker = "@:app:print" ascii wide
        $target1 = "Trezor Suite" ascii wide
        $target2 = "Ledger Live" ascii wide
        $target3 = "Ledger Wallet" ascii wide
        $field1 = "SeedData" ascii
        $field2 = "DeviceHardwareId" ascii
        $field3 = "DeviceName" ascii
        $c2 = "moonsand" ascii

    condition:
        filesize < 10MB and
        (
            ($hook1 and $marker) or
            (2 of ($target*) and 1 of ($field*)) or
            ($c2 and 2 of ($field*))
        )
}
