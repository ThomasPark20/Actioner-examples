rule Malware_TraderTraitor_FLATROOF : tradertraitor dprk macos
{
    meta:
        description = "Detects FLATROOF (macOS.Gaslight) ARM64 Rust backdoor deployed by TraderTraitor via weaponized Terraform repositories"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $path1 = "com.apple.iTunesCloud" ascii
        $name1 = "SystemUpdate" ascii fullword
        $c2_1 = "technicais.sytes.net" ascii
        $tg = "Telegram" ascii
        $keychain = "login.keychain-db" ascii
        $brave = "BraveSoftware" ascii
        $gatekeeper = "spctl" ascii
        $type_renderer = "--type=renderer" ascii

    condition:
        filesize < 20MB and
        (
            ($path1 and $name1) or
            $c2_1 or
            ($keychain and $tg and 1 of ($brave, $gatekeeper)) or
            ($type_renderer and $path1)
        )
}
