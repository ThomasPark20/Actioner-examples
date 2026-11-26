rule Malware_NuGet_Package_FakeJobAssessment
{
    meta:
        description = "Detects malicious NuGet packages (.nupkg) from the fake .NET job assessment supply chain campaign by matching package IDs and known malicious content patterns."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "ccf299e23471cd79b2f40f91ee6f48293893e6c626ef84b10ef0b3ba86a89770"
        severity = "critical"

    strings:
        $pkg1 = "VS_Builder.MSBuildAnalyzer" ascii wide nocase
        $pkg2 = "VS_Builder.WinUI3Controls" ascii wide nocase
        $pkg3 = "HappyOne.MSBuildAnalyzer" ascii wide nocase
        $pkg4 = "HappyOne.WinUI3Controls" ascii wide nocase
        $pkg5 = "WinUI.Button" ascii wide
        $pkg6 = "Web3TotalButton" ascii wide nocase
        $pkg7 = "RevertButtonIcon" ascii wide nocase
        $pkg8 = "WinUI3IconButton" ascii wide nocase
        $pkg9 = "WindowsAccentColorName" ascii wide nocase
        $nuspec = "<package xmlns" ascii
        $nuget_marker = ".nuspec" ascii

    condition:
        filesize < 50MB and
        ($nuspec or $nuget_marker) and
        2 of ($pkg*)
}
