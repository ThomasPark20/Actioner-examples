rule Malware_UAT11795_Starland_WLDR_Indicators
{
    meta:
        description = "Detects Starland RAT and WLDR C2 implant artifacts from UAT-11795 campaign via distinctive strings including mutex, encryption keys, C2 domains, and smart contract address"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $mutex = "f2j398fj239d8j23dkkskskkkkkkkkk" ascii wide
        $xor_key1 = "helo1" ascii wide
        $xor_key2 = "$m7*rYpry3" ascii wide
        $wldr_pass = "odg5t8mvssvh" ascii wide
        $contract = "0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba" ascii wide nocase
        $func_sel = "0xc659f3b8" ascii wide nocase
        $c2_1 = "windowscreenrepairnearme.com" ascii wide nocase
        $c2_2 = "aipythondevs.com" ascii wide nocase
        $c2_3 = "eorthopaedics.com" ascii wide nocase
        $c2_4 = "sastoro.com" ascii wide nocase
        $staging_1 = "web-devtools.com" ascii wide nocase
        $staging_2 = "zynaris.io" ascii wide nocase
        $task_prefix = "PythonLauncher-" ascii wide
        $proto_ver = "WSv1" ascii wide
        $tg_bot1 = "8384531459" ascii wide
        $tg_bot2 = "7993597060" ascii wide

    condition:
        2 of them
}

rule Malware_UAT11795_CastleStealer_Strings
{
    meta:
        description = "Detects CastleStealer info-stealer deployed by UAT-11795 via the CastleStealer name string or co-occurrence with campaign C2 domains"
        author = "Actioner"
        date = "2026-07-17"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "medium"

    strings:
        $s1 = "CastleStealer" ascii wide nocase
        $c2_1 = "windowscreenrepairnearme.com" ascii wide nocase
        $c2_2 = "aipythondevs.com" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($s1 or 2 of ($c2_*))
}
