rule Malware_SPECTRE_Windows_Implant
{
    meta:
        description = "Detects SPECTRE Windows implant via characteristic PDB paths, named pipe pattern, and API resolution strings associated with UAT-10147"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pdb1 = "x神订制全站劫持按浏览器语言跳转" ascii wide
        $pdb2 = "x神的自安装服务" ascii wide
        $pdb3 = "svchost\\x64\\Release\\service.pdb" ascii
        $pipe = "\\\\.\\pipe\\spectre_" ascii wide
        $api_register = "/api/v1/register" ascii
        $api_output = "/api/v1/output" ascii
        $ads = "drivers\\etc\\hosts:cache" ascii wide
        $web_header = "X-ID" ascii
        $web_param = "x9" ascii
        $efspotato = "EfsPotato" ascii wide
        $cmd_hashdump = "hashdump" ascii
        $cmd_chromedump = "chromedump" ascii
        $cmd_vaultdump = "vaultdump" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($pdb*) or
            ($pipe and 1 of ($api*)) or
            (3 of ($cmd*, $ads, $web_header, $web_param, $api_register, $api_output, $efspotato))
        )
}
