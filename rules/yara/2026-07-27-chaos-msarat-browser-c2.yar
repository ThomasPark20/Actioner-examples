import "pe"

rule Malware_Chaos_msaRAT_Rust_RAT
{
    meta:
        description = "Detects msaRAT Rust-based RAT used by Chaos ransomware group via Chrome DevTools Protocol binding names, Tokio runtime strings, and CDP command patterns embedded in the binary"
        author = "Actioner"
        date = "2026-07-27"
        reference = "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $binding1 = "msaOpen" ascii
        $binding2 = "msaClose" ascii
        $binding3 = "msaError" ascii
        $binding4 = "msaMessage" ascii
        $binding5 = "dataAck" ascii

        $tokio1 = "TOKIO_WORKER_THREADS" ascii
        $tokio2 = "the number of hardware threads is not known" ascii

        $cdp1 = "Runtime.addBinding" ascii
        $cdp2 = "Runtime.evaluate" ascii
        $cdp3 = "Page.setBypassCSP" ascii
        $cdp4 = "Target.createTarget" ascii
        $cdp5 = "Page.enable" ascii
        $cdp6 = "Runtime.enable" ascii

        $js1 = "Base64ToArrayBuffer" ascii
        $js2 = "RTCPeerConnection" ascii
        $js3 = "createDataChannel" ascii

        $crypto1 = "chacha20" ascii nocase
        $crypto2 = "poly1305" ascii nocase

        $export = "RUN" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (3 of ($binding*)) or
            (2 of ($binding*) and 2 of ($cdp*)) or
            (2 of ($binding*) and 1 of ($tokio*) and $export) or
            (all of ($cdp*) and 2 of ($js*) and 1 of ($crypto*))
        )
}
