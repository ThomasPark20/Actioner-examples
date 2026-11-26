rule Malware_NuGet_WinUIButton_Downloader
{
    meta:
        description = "Detects malicious WinUI.Button.dll NuGet package that downloads and executes payloads from GitHub using embedded tokens. Part of the fake .NET job assessment supply chain attack."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "9e58baccd25b009b80f093bbcaf007b1ca3ac763c9826e05e1352e64264d0d42"
        severity = "critical"

    strings:
        $s1 = "Core.Init" ascii wide
        $s2 = "Global\\MyUniqueApplicationGuid-12345" ascii wide
        $s3 = "Launcher.exe" ascii wide
        $s4 = "avast.exe" ascii wide
        $s5 = "Carol-White-Super" ascii
        $s6 = "WUIButton" ascii wide
        $github = "api.github.com/repos" ascii wide
        $aes_key = "NKz0WUpm4uBA9fcO8xN+xj87Ngke7RXPpHuflllgjuk=" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (3 of ($s*) or $aes_key or ($s2 and $s3) or ($s6 and $github))
}
