rule Malware_WLDR_C2_Agent
{
    meta:
        description = "Detects WLDR PowerShell C2 agent via mutex, protocol version tag, and encryption markers"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        hash = "d52540621dec5ed56cac8532f0e4fe10a7575c3e17e984f59646909fa587dd35"
        severity = "high"

    strings:
        $mutex = "f2j398fj239d8j23dkkskskkkkkkkkk" ascii wide
        $proto = "WSv1" ascii wide
        $pwd = "odg5t8mvssvh" ascii wide
        $c2path = "/command" ascii wide
        $amsi1 = "AmsiScanBuffer" ascii wide
        $etw1 = "EtwEventWrite" ascii wide

    condition:
        3 of them
}
