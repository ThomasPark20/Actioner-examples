rule Malware_Chaos_msaRAT_CDP_Bindings
{
    meta:
        description = "Detects msaRAT payload (lib.dll) via Chrome DevTools Protocol binding names and MSI Binary table reference used for covert WebRTC-based C2"
        author = "Actioner"
        date = "2026-07-23"
        reference = "https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $cdp1 = "msaOpen" ascii wide
        $cdp2 = "msaClose" ascii wide
        $cdp3 = "msaError" ascii wide
        $cdp4 = "msaMessage" ascii wide
        $cdp5 = "dataAck" ascii wide
        $msi_bin = "Bin_lib_EA2AEBC3" ascii wide
        $msi_ca = "CA_Run_EA2AEBC3" ascii wide
        $c2_domain = "is-01-ast.ols-img-12.workers.dev" ascii wide
        $signaling = "/token/v1/" ascii wide
        $export = "RUN" ascii fullword

    condition:
        (3 of ($cdp*)) or
        ($msi_bin and $export) or
        ($msi_ca and $export) or
        ($c2_domain and $signaling) or
        (2 of ($cdp*) and $c2_domain)
}
