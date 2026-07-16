rule Malware_StarlandRAT_Strings
{
    meta:
        description = "Detects Starland RAT Python loader via characteristic strings including XOR key, beacon paths, and encryption markers"
        author = "Actioner"
        date = "2026-07-16"
        reference = "https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/"
        severity = "high"

    strings:
        $xor_key1 = "helo1" ascii wide
        $xor_key2 = "$m7\\*rYpry3" ascii wide
        $uri1 = "/starlandfox" ascii wide
        $uri2 = "/x32remka" ascii wide
        $uri3 = "/dopfile" ascii wide
        $c2_1 = "windowscreenrepairnearme.com" ascii wide
        $c2_2 = "aipythondevs.com" ascii wide
        $beacon = "/feed/" ascii wide
        $polygon = "0xc659f3b8" ascii wide
        $contract = "0x6ae382ed2154cc84c6672e4e908cd2c69c1b35ba" ascii wide

    condition:
        3 of them
}
