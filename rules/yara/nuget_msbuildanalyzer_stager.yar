rule Malware_NuGet_MSBuildAnalyzer_Stager
{
    meta:
        description = "Detects malicious MSBuildAnalyzer.dll delivered via trojanized NuGet packages in fake .NET job assessment campaign. The DLL acts as a build-time stager that downloads payloads from GitHub and stages DLL sideloading."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "352b04dac5f63208f45c7c7326ed06c6fa8ae2752e4cdafff0cfe649ebaeabe2"
        severity = "critical"

    strings:
        $s1 = "_environmentProbeKeyFragment" ascii wide
        $s2 = "_diagnosticHostSourceKeyFragment" ascii wide
        $s3 = "BuildPipeline" ascii wide
        $s4 = "OskSupport.dll" ascii wide
        $s5 = "osk.exe" ascii wide
        $aes_key = "sPq0nrUkrTYj5qUvdsRYAlVQ7MPQBwCuIB17ghrz0vM=" ascii
        $b64_1 = "CxcXExBZTEwC" ascii
        $b64_2 = "t6WyuLSgnp2ckPCI/JKFkJ2ck7C3pbK6vLC37fc=" ascii
        $github_api = "api.github.com/repos" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (3 of ($s*) or ($aes_key) or (2 of ($b64*)) or ($s1 and $github_api) or ($s2 and $github_api))
}
