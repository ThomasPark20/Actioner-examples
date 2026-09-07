rule Exploit_FalconFlank_PoC
{
    meta:
        description = "Detects FalconFlank PoC exploit binary targeting CrowdStrike Falcon privilege escalation"
        author = "Actioner"
        date = "2026-09-04"
        reference = "https://github.com/MSNightmare/FalconFlank"
        severity = "critical"

    strings:
        $pipe = "FALCONFLANK" ascii wide
        $dll_target = "bcrypt.dll" ascii wide
        $ps_path = "WindowsPowerShell\\v1.0" ascii wide
        $snake = "MY_SNAKE_IS_SOLID" ascii wide
        $flanker = "Flanker_" ascii wide
        $task = "MareBackup" ascii wide
        $task_path = "\\Microsoft\\Windows\\Application Experience" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $pipe and
        3 of ($dll_target, $ps_path, $snake, $flanker, $task, $task_path)
}
