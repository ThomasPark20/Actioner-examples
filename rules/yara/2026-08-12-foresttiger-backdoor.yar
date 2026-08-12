import "hash"

rule Lazarus_ForestTiger_Backdoor
{
    meta:
        description = "Detects ForestTiger backdoor used by Lazarus Group in Operation Dream Job via known hashes and shared C2/command infrastructure strings"
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
        severity = "critical"
        tlp = "WHITE"
        hash1 = "72dccae85e062f541fecad9ec7a18a3123e7ae5ac5d53c91709b53a46dbbd289"
        hash2 = "231b1ef8b95bf77887d5377e2a60f649035e78f543af1b82877db36a5759d858"
        hash3 = "6da9b1e6f3315ceb77dd14a937a26cc3602bf6a7e2c2ecafb3c65ce5319837be"
        hash4 = "a0578a2b7821d7e2c573530648f26d7a0d98b373ab24fb7f0c792736761e542d"
        hash5 = "82268052f94df6f4870d02e57b18d4c54136cc7a8c8d80ad162631f99462c943"

    strings:
        $c2_1 = "envell.xyz" ascii wide
        $c2_2 = "enveil.online" ascii wide
        $c2_3 = "uxtramine.org" ascii wide

        $cmd_1 = "ZIPDOWNLOAD" ascii wide
        $cmd_2 = "DEFAULTSLEEP" ascii wide
        $cmd_3 = "GET_CONFIG" ascii wide
        $cmd_4 = "SET_CONFIG" ascii wide

        $api_1 = "RtlCreateUserThread" ascii
        $api_2 = "NtAllocateVirtualMemory" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            hash.sha256(0, filesize) == "72dccae85e062f541fecad9ec7a18a3123e7ae5ac5d53c91709b53a46dbbd289" or
            hash.sha256(0, filesize) == "231b1ef8b95bf77887d5377e2a60f649035e78f543af1b82877db36a5759d858" or
            hash.sha256(0, filesize) == "6da9b1e6f3315ceb77dd14a937a26cc3602bf6a7e2c2ecafb3c65ce5319837be" or
            hash.sha256(0, filesize) == "a0578a2b7821d7e2c573530648f26d7a0d98b373ab24fb7f0c792736761e542d" or
            hash.sha256(0, filesize) == "82268052f94df6f4870d02e57b18d4c54136cc7a8c8d80ad162631f99462c943" or
            (1 of ($c2_*) and 2 of ($cmd_*)) or
            (2 of ($c2_*) and 1 of ($api_*))
        )
}
