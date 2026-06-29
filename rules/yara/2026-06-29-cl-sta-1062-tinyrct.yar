import "pe"

rule APT_CLSTA1062_TinyRCT_Backdoor
{
    meta:
        description = "Detects TinyRCT backdoor used by CL-STA-1062 via hardcoded AES key, characteristic strings, and behavioral indicators"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/"
        hash = "4e1f8888d020decd09799ec946f1bf677cac6612b24582ddbf4d8ede425d8384"
        severity = "critical"

    strings:
        $aes_key = "ThisIsASecretKey87654321" ascii wide
        $name1 = "TinyRCT" ascii wide
        $name2 = "PerfWatson2" ascii wide
        $file1 = "PerfWatson2.exe" ascii wide
        $task1 = "GoogleUpdaterTaskSystem" ascii wide
        $task2 = "ACE7A46F-50FD-481C-AB32-3D838871DB40" ascii wide
        $loader = "MyAppDomainManager" ascii wide
        $cfg = "chrome_setup.exe.config" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $aes_key or
            ($name1 and 1 of ($file1, $task1, $task2)) or
            (2 of ($task1, $task2, $loader, $cfg)) or
            ($name2 and $task1)
        )
}

rule APT_CLSTA1062_TinyRCT_Downloader
{
    meta:
        description = "Detects TinyRCT downloader component (MyAppDomainManager.dll) used in AppDomainManager injection attacks by CL-STA-1062"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/"
        hash = "cbfe8de6ffadbb1d396f61e63eb18e8b11c29527c1528641e3223d4c516cf7c3"
        severity = "high"

    strings:
        $s1 = "MyAppDomainManager" ascii wide
        $s2 = "chrome_setup" ascii wide
        $s3 = "AppDomainManager" ascii wide
        $url1 = "139.180.134.221" ascii
        $url2 = "sdksdk608" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            ($s1 and ($s2 or $s3)) or
            ($s1 and 1 of ($url*)) or
            ($url2 and 1 of ($s*))
        )
}

rule APT_CLSTA1062_ChromeSetup_Archive
{
    meta:
        description = "Detects the malicious chrome_setup.zip archive used to deliver TinyRCT via AppDomainManager injection"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/"
        hash = "00e09754526d0fe836ba27e3144ae161b0ecd3774abec5560504a16a67f0087c"
        severity = "high"

    strings:
        $zip_hdr = { 50 4B 03 04 }
        $f1 = "chrome_setup.exe" ascii
        $f2 = "chrome_setup.exe.config" ascii
        $f3 = "MyAppDomainManager.dll" ascii

    condition:
        $zip_hdr at 0 and
        filesize < 50MB and
        all of ($f*)
}
