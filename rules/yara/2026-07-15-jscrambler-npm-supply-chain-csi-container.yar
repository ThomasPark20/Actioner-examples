rule Supply_Chain_jscrambler_IronWorm_CSI_Container
{
    meta:
        description = "Detects the CSI binary container format used by the compromised jscrambler npm package to bundle IronWorm infostealer payloads"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://socket.dev/blog/jscrambler-supply-chain-attack"
        hash = "a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86"
        severity = "critical"

    strings:
        $csi_magic = { 1B 43 53 49 01 }

    condition:
        $csi_magic at 0 and filesize > 1MB and filesize < 15MB
}
