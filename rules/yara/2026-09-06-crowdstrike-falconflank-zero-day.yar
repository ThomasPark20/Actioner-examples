rule FalconFlank_Exploit_Binary
{
    meta:
        description = "Detects the FalconFlank privilege escalation exploit binary targeting CrowdStrike Falcon Sensor"
        author = "Actioner"
        date = "2026-09-06"
        reference = "https://github.com/MSNightmare/FalconFlank"
        hash = ""

    strings:
        $pipe = "\\??\\pipe\\FALCONFLANK" ascii wide
        $tempdir = "Flanker_" ascii wide
        $task = "MareBackup" ascii wide
        $dllpath = "WindowsPowerShell\\v1.0\\bcrypt.dll" ascii wide
        $taskpath = "\\Microsoft\\Windows\\Application Experience" ascii wide

        $ole2_sig = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        uint16(0) == 0x5A4D and
        3 of ($pipe, $tempdir, $task, $dllpath, $taskpath) and
        $ole2_sig
}
