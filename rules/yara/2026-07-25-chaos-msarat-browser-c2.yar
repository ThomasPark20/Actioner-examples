import "pe"

rule Malware_Chaos_msaRAT_DLL
{
    meta:
        description = "Detects the msaRAT DLL payload used by the Chaos ransomware group. Matches characteristic CDP binding names, Tokio runtime strings, and WebRTC signaling artifacts found in the Rust-compiled lib.dll."
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // CDP binding names unique to msaRAT
        $bind1 = "msaOpen" ascii wide
        $bind2 = "msaClose" ascii wide
        $bind3 = "msaError" ascii wide
        $bind4 = "msaMessage" ascii wide
        $bind5 = "dataAck" ascii wide

        // Tokio runtime strings in Rust binary
        $tokio1 = "TOKIO_WORKER_THREADS" ascii
        $tokio2 = "the number of hardware threads is not known for the target platform" ascii

        // CDP commands used by the RAT
        $cdp1 = "Target.createTarget" ascii
        $cdp2 = "Page.setBypassCSP" ascii
        $cdp3 = "Runtime.evaluate" ascii
        $cdp4 = "Page.enable" ascii
        $cdp5 = "Runtime.enable" ascii

        // WebRTC/signaling strings
        $webrtc1 = "RTCPeerConnection" ascii wide
        $webrtc2 = "/token/v1/" ascii
        $webrtc3 = "workers.dev" ascii

        // Encryption identifiers
        $enc1 = "chacha20" ascii nocase
        $enc2 = "poly1305" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (3 of ($bind*)) or
            (2 of ($bind*) and 2 of ($cdp*)) or
            (2 of ($bind*) and 1 of ($tokio*) and 1 of ($webrtc*)) or
            (2 of ($bind*) and 1 of ($enc*) and 1 of ($cdp*))
        )
}

rule Malware_Chaos_msaRAT_MSI_Installer
{
    meta:
        description = "Detects malicious MSI installer used to deliver the msaRAT payload. Matches the Binary table entry name and DLL export function used during custom action execution."
        author = "Actioner"
        date = "2026-07-25"
        reference = "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"
        tlp = "WHITE"
        severity = "high"

    strings:
        // MSI Binary table entry name
        $msi1 = "Bin_lib_EA2AEBC3" ascii wide
        // Custom action name
        $msi2 = "CA_Run_EA2AEBC3" ascii wide
        // Export function
        $msi3 = "RUN" ascii fullword

        // MSI magic header
        $msi_header = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $msi_header at 0 and
        filesize < 50MB and
        (
            ($msi1 and $msi3) or
            ($msi2 and $msi3) or
            ($msi1 and $msi2)
        )
}
