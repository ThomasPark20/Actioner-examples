rule Malware_Starland_RAT_Python_Loader
{
    meta:
        description = "Detects compiled Python-based Starland RAT loader via characteristic XOR key, C2 paths, sandbox check strings, and API resolution patterns used by UAT-11795"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "critical"

    strings:
        $c2_1 = "windowscreenrepairnearme.com" ascii wide
        $c2_2 = "aipythondevs.com" ascii wide
        $c2_cmd = "/command" ascii wide

        $sandbox_1 = "WDAGUtilityAccount" ascii wide
        $sandbox_2 = "Cuckoo" ascii wide
        $sandbox_3 = "Any.Run" ascii wide

        $api_1 = "VirtualAllocEx" ascii wide
        $api_2 = "WriteProcessMemory" ascii wide
        $api_3 = "CreateRemoteThread" ascii wide
        $api_4 = "QueueUserAPC" ascii wide
        $api_5 = "ResumeThread" ascii wide
        $api_6 = "CreateProcessA" ascii wide

        $cmd_1 = "shellexecute" ascii wide
        $cmd_2 = "x32" ascii wide
        $cmd_3 = "x64" ascii wide
        $cmd_4 = "download" ascii wide

        $enc_key = "helo1" ascii wide
        $license = "LICENSE.txt" ascii wide

    condition:
        filesize < 50MB and
        (
            (1 of ($c2_*) and 2 of ($api_*)) or
            (1 of ($c2_*) and $enc_key) or
            (2 of ($sandbox_*) and 2 of ($api_*) and $enc_key) or
            (3 of ($cmd_*) and 1 of ($c2_*)) or
            ($license and $enc_key and 2 of ($api_*))
        )
}

rule Malware_WLDR_C2_Agent_PowerShell
{
    meta:
        description = "Detects WLDR C2 PowerShell agent via hardcoded encryption password, mutex string, protocol identifiers, and AES/PBKDF2 configuration used by UAT-11795"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "critical"

    strings:
        $password = "odg5t8mvssvh" ascii wide nocase
        $mutex = "f2j398fj239d8j23dkkskskkkkkkkkk" ascii wide
        $proto = "WSv1" ascii wide

        $crypto_1 = "PBKDF2" ascii wide nocase
        $crypto_2 = "AES" ascii wide nocase
        $crypto_3 = "HMAC" ascii wide nocase
        $crypto_4 = "SHA256" ascii wide nocase

        $ps_1 = "Runspace" ascii wide nocase
        $ps_2 = "ICorRuntimeHost" ascii wide nocase
        $ps_3 = "AmsiScanBuffer" ascii wide nocase
        $ps_4 = "EtwEventWrite" ascii wide nocase
        $ps_5 = "VirtualProtect" ascii wide nocase

        $wldr_1 = "New-ScheduledTask" ascii wide nocase
        $wldr_2 = "Global:" ascii wide nocase

    condition:
        filesize < 10MB and
        (
            $password or
            $mutex or
            ($proto and 2 of ($crypto_*)) or
            ($proto and 2 of ($ps_*)) or
            (2 of ($ps_*) and 2 of ($crypto_*) and 1 of ($wldr_*))
        )
}

rule Malware_Starland_RAT_HTA_Dropper
{
    meta:
        description = "Detects HTA dropper files used in UAT-11795 ClickFix delivery chain via embedded VBScript with Russian language comments and staging domain references"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $hta_tag = "<HTA:APPLICATION" ascii nocase
        $vbs_tag = "<script language" ascii nocase

        $ru_comment = {D0 94 D0 BE D0 B1 D0 B0 D0 B2 D0 BB D0 B5 D0 BD D0 B8 D0 B5}

        $domain_1 = "eorthopaedics.com" ascii wide
        $domain_2 = "sastoro.com" ascii wide
        $domain_3 = "zynaris.io" ascii wide
        $domain_4 = "alphabitcapital.info" ascii wide

        $staging_1 = "/feed/" ascii wide
        $staging_2 = "/alpha/" ascii wide

        $bot_1 = "8384531459" ascii wide
        $bot_2 = "7993597060" ascii wide

    condition:
        filesize < 2MB and
        (
            ($hta_tag and 1 of ($domain_*)) or
            ($vbs_tag and 1 of ($domain_*) and 1 of ($staging_*)) or
            ($hta_tag and $ru_comment and 1 of ($staging_*)) or
            (1 of ($domain_*) and 1 of ($bot_*))
        )
}

rule Malware_UAT11795_Shellcode_Payload
{
    meta:
        description = "Detects shellcode payloads hosted on UAT-11795 infrastructure by matching staging URL paths and domain indicators"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $url_1 = "web-devtools.com/starlandfox" ascii wide
        $url_2 = "web-devtools.com/x32remka" ascii wide
        $url_3 = "web-devtools.com/dopfile" ascii wide
        $url_4 = "web-devtools.com/file.zip" ascii wide

        $fallback_key = "$m7*rYpry3" ascii wide
        $contract = "0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba" ascii wide nocase
        $selector = "0xc659f3b8" ascii wide

    condition:
        filesize < 50MB and
        (
            1 of ($url_*) or
            ($contract and $selector) or
            ($fallback_key and ($contract or $selector))
        )
}
