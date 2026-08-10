// Actioner - North Korea-Attributed npm Supply Chain Attack (2026-07-30)
// References:
//   https://thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html
//   https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html

rule NPM_NK_Typo_Crypto_Malicious_Package
{
    meta:
        description = "Detects the malicious typo-crypto npm package (core.js payload) used by North Korean Sapphire Sleet for stage-two delivery via npmjs.store C2"
        author = "Actioner"
        date = "2026-07-30"
        reference = "https://thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html"
        hash = "64edea611ad8e383c09495a7a6f7afd4fb86b88136c331ddf787bf0285259bf3"
        severity = "high"

    strings:
        $c2_domain = "npmjs.store" ascii wide
        $xor_key = "01042025" ascii wide
        $trigger = "0098273" ascii wide
        $core_js = "core.js" ascii
        $pkg_name = "typo-crypto" ascii

    condition:
        filesize < 1MB and
        $c2_domain and
        (2 of ($xor_key, $trigger, $core_js, $pkg_name))
}

rule NPM_NK_Debug_Chalk_Wallet_Drainer
{
    meta:
        description = "Detects browser-side wallet-draining interceptor injected into compromised debug/chalk npm packages, hooking fetch/XMLHttpRequest and wallet APIs"
        author = "Actioner"
        date = "2026-07-30"
        reference = "https://thehackernews.com/2026/07/amazon-links-debug-and-chalk-npm-hijack.html"
        severity = "medium"

    strings:
        $hook_fetch = "fetch" ascii
        $hook_xhr = "XMLHttpRequest" ascii
        $wallet_api = "wallet" ascii nocase
        $rewrite_addr = "transaction" ascii nocase
        $signing = "signing" ascii nocase
        $npmjs_store = "npmjs.store" ascii

    condition:
        filesize < 5MB and
        $npmjs_store and
        2 of ($hook_fetch, $hook_xhr, $wallet_api, $rewrite_addr, $signing)
}

rule NPM_NK_Joyfill_RAT_Implant
{
    meta:
        description = "Detects the RAT implant delivered via compromised @joyfill npm packages, linked to PolinRider/DEV#POPPER cluster"
        author = "Actioner"
        date = "2026-07-30"
        reference = "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
        severity = "medium"

    strings:
        $clip_win = "Get-Clipboard" ascii wide
        $clip_mac = "pbpaste" ascii
        $clip_linux1 = "xclip" ascii
        $clip_linux2 = "xsel" ascii
        $upload = "upload" ascii nocase
        $checkin = "check-in" ascii nocase
        $joyfill = "joyfill" ascii nocase

    condition:
        filesize < 5MB and
        (2 of ($clip_win, $clip_mac, $clip_linux1, $clip_linux2)) and
        1 of ($upload, $checkin, $joyfill)
}
