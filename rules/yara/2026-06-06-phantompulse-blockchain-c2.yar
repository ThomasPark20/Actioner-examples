rule Malware_PHANTOMPULSE_RAT_Strings
{
    meta:
        description = "Detects PHANTOMPULSE RAT via characteristic debug strings and C2 API paths observed in the REF6598 campaign"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole"
        hash = "33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f"
        severity = "critical"

    strings:
        $api1 = "/v1/telemetry/report" ascii wide
        $api2 = "/v1/telemetry/tasks/" ascii wide
        $api3 = "/v1/telemetry/upload/" ascii wide
        $api4 = "/v1/telemetry/result" ascii wide
        $api5 = "/v1/telemetry/keylog/" ascii wide

        $dbg1 = "PhantomInject: host PID=%lu" ascii
        $dbg2 = "[UNINSTALL 2/6]" ascii
        $dbg3 = "inject: shellcode detected" ascii
        $dbg4 = "ManualMap: thread hijacked and resumed" ascii
        $dbg5 = "FindHostProcessEx: scan stats" ascii
        $dbg6 = "KeylogResolveAPIs: ENTER" ascii

        $task1 = "DotNetSvcUpdateTask" ascii wide
        $task2 = "DotNetSvcCoreTask" ascii wide
        $task3 = "DotNetSvcUserTask" ascii wide

        $mutex = "hVNBUORXNiFLhYYh" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            3 of ($api*) or
            2 of ($dbg*) or
            (2 of ($task*) and $mutex)
        )
}

rule Malware_PHANTOMPULL_Loader
{
    meta:
        description = "Detects PHANTOMPULL loader (syncobs.exe) used in the REF6598 campaign to stage PHANTOMPULSE RAT"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.elastic.co/security-labs/phantom-in-the-vault"
        hash = "70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980"
        severity = "high"

    strings:
        $s1 = "/v1/updates/check?build=payloads" ascii wide
        $s2 = "svcagent.dll" ascii wide
        $s3 = "DllRegisterServer" ascii wide
        $s4 = "AssetMon" ascii wide

        $tick = { 48 83 C4 80 FF 15 ?? ?? ?? ?? 83 F8 FE 75 }
        $djb2 = { 45 8B 0C 83 41 BA A7 C6 67 4E 49 01 C9 45 8A 01 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 3MB and
        (
            ($s1 and 1 of ($s2, $s3, $s4)) or
            ($tick and $djb2) or
            (3 of ($s*))
        )
}

rule Malware_PHANTOMPULSE_Blockchain_C2_Config
{
    meta:
        description = "Detects PHANTOMPULSE RAT via embedded blockchain C2 resolver configuration including Blockscout hostnames and wallet address"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.elastic.co/security-labs/blockchain-c2-phantompulse-rat-sinkhole"
        severity = "high"

    strings:
        $wallet = "0xc117688c530b660e15085bF3A2B664117d8672aA" ascii wide
        $bs1 = "eth.blockscout.com" ascii wide
        $bs2 = "base.blockscout.com" ascii wide
        $bs3 = "optimism.blockscout.com" ascii wide
        $api = "module=account&action=txlist" ascii wide

        $xor_key = { F7 7C 8E 40 DF C1 7B E5 E7 4D 86 79 D5 B3 53 41 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $wallet or
            (2 of ($bs*) and $api) or
            ($xor_key and 1 of ($bs*))
        )
}
