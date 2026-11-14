rule SCKit_ToolboxRelayUploader
{
    meta:
        description = "Detects the SCKit ToolboxRelayUploader executable used to distribute payloads through ScreenConnect Shared Toolbox"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash = "8cb5f48bbe70b5248db7f327f3d1ad6649df5c767d2a7e0711ee147fd92e06af"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $toolbox_relay = "ToolboxRelayUploader" ascii wide
        $screenconnect = "ScreenConnect" ascii wide
        $shared_toolbox = "SharedToolbox" ascii wide
        $upload = "Upload" ascii wide
        $relay = "Relay" ascii wide
        $session_events = "SessionEvents" ascii wide

    condition:
        filesize < 10MB and
        uint16(0) == 0x5A4D and
        $toolbox_relay and
        $screenconnect and
        2 of ($shared_toolbox, $upload, $relay, $session_events)
}
