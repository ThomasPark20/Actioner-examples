rule Malware_NuGet_MSBuildTargets_Trojanized
{
    meta:
        description = "Detects trojanized MSBuild .targets files used by malicious NuGet packages to execute code after every build. The targets file forces re-execution by referencing a non-existent output file."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "33510d8e48c26279c0c212b4e6e5f95b7f0a116061eae7f50241f81903be5b6b"
        severity = "high"

    strings:
        $s1 = "ForceExecuteNonExistenFile" ascii wide nocase
        $s2 = "ExecuteInlineCSharpTarget" ascii wide nocase
        $s3 = "MSBuildAnalyzer.dll" ascii wide
        $s4 = "AfterTargets=\"Build\"" ascii nocase
        $s5 = "IgnoreExitCode" ascii nocase
        $s6 = "ContinueOnError" ascii nocase

    condition:
        filesize < 100KB and
        ($s1 or ($s2 and $s3) or ($s3 and $s4 and ($s5 or $s6)))
}
