rule Malware_DeviceManager_RAT_DOUBLECUP
{
    meta:
        description = "Detects DeviceManager RAT delivered by DOUBLECUP loader-as-a-service based on characteristic strings and behavioral markers"
        author = "Actioner"
        date = "2026-08-04"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "6e08cb5602f63bee2b40739167b4aef77763bc8fb47b4839ca2fc1607ad35cba"
        severity = "high"

    strings:
        $config = "config.json" ascii
        $log = "agent.log" ascii
        $task1 = "MicroUpdaterV1" ascii wide
        $task2 = "PythonAppUpdater" ascii wide
        $dir = "Microsoft.PythonApp_" ascii
        $func1 = "get_data_selector" ascii
        $func2 = "device_hash" ascii
        $func3 = "build_tag_token" ascii
        $func4 = "global_key" ascii
        $eth1 = "eth_call" ascii
        $eth2 = "0xc027490af56a9d7050fc259ecd03da1580b84aae" ascii nocase
        $eth3 = "0x1dcf296b" ascii
        $dns1 = "microsoft.com" ascii
        $dns2 = "_dm_task" ascii

    condition:
        filesize < 5MB and
        (
            (3 of ($func*) and 1 of ($eth*)) or
            (2 of ($task*) and $dir) or
            ($eth2 and 1 of ($func*)) or
            ($config and $log and 2 of ($func*)) or
            (2 of ($dns*) and 2 of ($func*))
        )
}
