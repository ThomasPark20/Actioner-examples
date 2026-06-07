rule Malware_PHANTOMPULSE_RAT_Strings
{
    meta:
        description = "Detects PHANTOMPULSE RAT via characteristic debug strings found in samples"
        author = "Actioner"
        date = "2026-06-07"
        reference = "https://www.elastic.co/security-labs/phantom-in-the-vault"
        hash = "33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f"
        hash2 = "9e3890d43366faec26523edaf91712640056ea2481cdefe2f5dfa6b2b642085d"
        severity = "critical"

    strings:
        $a = "[UNINSTALL 2/6] Removing Scheduled Task..." ascii fullword
        $b = "PhantomInject: host PID=%lu" ascii fullword
        $c = "inject: shellcode detected -> InjectShellcodePhantom" ascii fullword
        $d = "inject: shellcode detected, using phantom section hijack" ascii fullword
        $e = "[HEIS] encrypt_text_only ENTER" ascii
        $f = "DbgNexumLoop64: stage 6 -> stub" ascii
        $g = "ManualMap: thread hijacked and resumed" ascii
        $h = "UnhookNtdll: ntdll base = %p" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        3 of them
}

rule Malware_PHANTOMPULSE_Loader_SyncObs
{
    meta:
        description = "Detects PHANTOMPULL loader (syncobs.exe) used in REF6598 campaign"
        author = "Actioner"
        date = "2026-06-07"
        reference = "https://www.elastic.co/security-labs/phantom-in-the-vault"
        hash = "70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980"
        severity = "high"

    strings:
        $mutex = "hVNBUORXNiFLhYYh" ascii fullword
        $task1 = "DotNetSvcUpdateTask" ascii fullword
        $task2 = "DotNetSvcCoreTask" ascii fullword
        $task3 = "DotNetSvcUserTask" ascii fullword
        $path = "\\AssetMon\\svcagent.dll" ascii
        $api1 = "/v1/telemetry/report" ascii
        $api2 = "/v1/telemetry/tasks/" ascii
        $api3 = "/v1/updates/check?build=payloads" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($mutex or 2 of ($task*) or ($path and 1 of ($api*)))
}
