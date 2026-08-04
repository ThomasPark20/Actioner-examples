/*
 * Actioner - CaptiveCrunch / Midnight Blizzard Hotel Wi-Fi Campaign
 * Reference: https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
 * Date: 2026-08-04
 * Confidence: high
 * Sample: untested (no real sample available; logic validated against published string indicators)
 */

rule APT29_CornFlake_RAT : CaptiveCrunch
{
    meta:
        description = "Detects CornFlake RAT used by Storm-2945/Midnight Blizzard in the CaptiveCrunch campaign via distinctive strings"
        author = "Actioner"
        date = "2026-08-04"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        hash = "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593"
        severity = "critical"

    strings:
        $svc_name = "svchost32" ascii wide
        $svc_display = "Cloud Sync Service" ascii wide
        $svc_desc = "Synchronizes files with the cloud storage provider" ascii wide
        $config = "sync.dat" ascii wide
        $fake1 = "winupdate" ascii
        $fake2 = "directx" ascii
        $fake3 = "vcredist" ascii
        $fake4 = "sysopt" ascii
        $fake5 = "netfix" ascii
        $fake6 = "pdfview" ascii
        $beacon = "/t/pixel.gif?m=" ascii
        $tool_uri = "/cdn/chunks/polyfill-7e2b.min.js" ascii
        $exfil_uri = "/t/event" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            ($svc_name and $svc_display and $svc_desc) or
            ($svc_name and $config and 2 of ($fake*)) or
            ($beacon and $tool_uri and $exfil_uri)
        )
}
