rule SCKit_RelayTrap_CSharp_Source
{
    meta:
        description = "Detects the SCKit RelayTrap C# source file or compiled binary that replaces the legitimate ScreenConnect Guest client to intercept technician sessions via CVE-2026-84869"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash = "3c7a98f0fdb6235b8076319c74dc1085f7b349b6d750416dd0cadb07d7972ec4"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $relay_trap = "RelayTrap" ascii wide
        $transfer_files = "TransferFilesMessage" ascii wide
        $file_action_run = "FileAction.Run" ascii wide
        $can_be_elevated = "canBeElevated" ascii wide
        $screenconnect_ns = "ScreenConnect" ascii wide
        $endpoint_status = "EndPointStatusMessage" ascii wide
        $guest_process = "ScreenConnect.WindowsClient" ascii wide
        $trap_watch = "TrapWatch" ascii wide

    condition:
        filesize < 2MB and
        $relay_trap and
        $screenconnect_ns and
        (
            ($transfer_files and $file_action_run) or
            ($can_be_elevated and $endpoint_status) or
            ($guest_process and $trap_watch and 5 of them)
        )
}
