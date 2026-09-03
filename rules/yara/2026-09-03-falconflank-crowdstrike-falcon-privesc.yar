rule FalconFlank_PoC_Binary
{
    meta:
        author = "Actioner"
        description = "Detects the FalconFlank PoC binary targeting CrowdStrike Falcon Sensor privilege escalation via DLL hijacking of bcrypt.dll"
        date = "2026-09-03"
        reference = "https://github.com/MSNightmare/FalconFlank"

    strings:
        $pipe = "\\\\.\\pipe\\FALCONFLANK" wide ascii
        $dir_prefix = "Flanker_" wide ascii
        $task_name = "MareBackup" wide ascii
        $task_path = "\\Microsoft\\Windows\\Application Experience" wide ascii
        $dll_target = "WindowsPowerShell\\v1.0\\bcrypt.dll" wide ascii
        $api1 = "CreateFileTransacted" ascii
        $api2 = "NtCreateFile" ascii
        $api3 = "NtSetInformationFile" ascii
        $com1 = "ITaskService" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($pipe or $task_name) and
        2 of ($dir_prefix, $task_path, $dll_target) and
        2 of ($api1, $api2, $api3, $com1)
}

rule FalconFlank_PoC_Payload_DLL
{
    meta:
        author = "Actioner"
        description = "Detects the embedded OLE payload DLL dropped by FalconFlank PoC as bcrypt.dll replacement"
        date = "2026-09-03"
        reference = "https://github.com/MSNightmare/FalconFlank"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $flanker_str = "Flanker" wide ascii
        $bcrypt_export = "BCryptOpenAlgorithmProvider" ascii
        $bcrypt_export2 = "BCryptEncrypt" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 200KB and
        $ole_magic and
        ($flanker_str or (1 of ($bcrypt_export*)))
}
