rule Adform_Supply_Chain_Crypto_Stealer
{
    meta:
        description = "Detects malicious JavaScript injected into Adform trackpoint-async.js for cryptocurrency address swapping"
        author = "Actioner CTI"
        date = "2026-08-03"
        reference = "https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/"
        hash = "02ff86c7f9fe609a753ff15bda90baa3c3e0d4a2e559ec4fcf8a3de0954b7c55"
        severity = "critical"

    strings:
        $trackpoint = "trackpoint-async" ascii
        $adform_fn1 = "setCookie" ascii
        $adform_fn2 = "readCookie" ascii
        $adform_fn3 = "readFPCookie" ascii

        $clipboard1 = "navigator.clipboard" ascii
        $clipboard2 = "readText" ascii
        $clipboard3 = "writeText" ascii
        $clipboard4 = "setInterval" ascii

        $crypto_btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $crypto_eth = /0x[0-9a-fA-F]{40}/ ascii
        $crypto_trx = /T[A-Za-z1-9]{33}/ ascii

        $c2_ip = "84.32.102.230" ascii
        $c2_port = "7744" ascii

        $event_copy = "addEventListener" ascii
        $event_type1 = "\"copy\"" ascii
        $event_type2 = "\"cut\"" ascii
        $event_type3 = "\"paste\"" ascii

        $dom_walk = "TEXT_NODE" ascii
        $contenteditable = "contenteditable" ascii
        $valuesetter = "valueSetter" ascii

    condition:
        filesize < 2MB and
        $trackpoint and
        (
            ($c2_ip and $c2_port) or
            (3 of ($clipboard*) and 2 of ($crypto_*)) or
            (2 of ($clipboard*) and 2 of ($event_type*) and $dom_walk) or
            (3 of ($adform_fn*) and 2 of ($clipboard*) and any of ($crypto_*)) or
            ($event_copy and $contenteditable and $valuesetter)
        )
}

rule Adform_Crypto_Stealer_JS_Clipboard_Hijack
{
    meta:
        description = "Detects JavaScript clipboard hijacking patterns consistent with Adform supply-chain crypto stealer"
        author = "Actioner CTI"
        date = "2026-08-03"
        reference = "https://thehackernews.com/2026/08/hackers-poison-adform-script-to-swap.html"
        severity = "high"

    strings:
        $clip_read = "navigator.clipboard.readText" ascii
        $clip_write = "navigator.clipboard.writeText" ascii
        $interval = "setInterval" ascii

        $evt1 = "addEventListener" ascii
        $evt_copy = "\"copy\"" ascii
        $evt_paste = "\"paste\"" ascii
        $evt_input = "\"input\"" ascii

        $dom_text = "TEXT_NODE" ascii
        $dom_edit = "contenteditable" ascii
        $dom_setter = "defineProperty" ascii

        $c2_beacon = "84.32.102.230" ascii

    condition:
        filesize < 2MB and
        (
            ($c2_beacon) or
            ($clip_read and $clip_write and $interval and 2 of ($evt*) and ($dom_text or $dom_edit or $dom_setter))
        )
}
