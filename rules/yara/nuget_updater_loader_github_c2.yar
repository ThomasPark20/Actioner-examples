rule Malware_NuGet_UpdaterLoader_GithubC2
{
    meta:
        description = "Detects the updater.exe/msedgewebview2.exe loader used as C2 agent in the malicious NuGet package campaign. Uses GitHub repositories as two-way C2 channels with CppHttp User-Agent."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "56e899eb1d5c967cbe760d1b7ac409fb9420b862c122ef7ec2a2aa6469a503a7"
        severity = "critical"

    strings:
        $ua1 = "CppHttp/1.0" ascii wide
        $ua2 = "MyUpdater" ascii wide
        $cjson1 = "cJSON_Parse" ascii
        $cjson2 = "cJSON_GetObjectItem" ascii
        $github1 = "api.github.com" ascii wide
        $github2 = "raw.githubusercontent.com" ascii wide
        $log1 = "log1.dat" ascii wide
        $log2 = "log2.dat" ascii wide
        $pass1 = "asdnbvHKJF&^*DSFKJEfasdljfa;!" ascii
        $pass2 = "!fjka&k34534*HJKHNT,.sdkr9i'sdfgjkjlkjserft" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($ua1 and 1 of ($cjson*)) or
            ($ua2 and 1 of ($github*)) or
            (1 of ($log*) and 1 of ($github*) and 1 of ($pass*)) or
            (2 of ($pass*))
        )
}
