rule SCKit_Panel_Lateral_Script
{
    meta:
        description = "Detects the SCKit Panel-Lateral PowerShell scripts used for ScreenConnect session cookie theft and console distribution"
        author = "Actioner"
        date = "2026-11-14"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/"
        hash1 = "94b93c649b0ae0281352da9d01761fa9195ab1e6ac7010af3b9ba1646355eb11"
        hash2 = "7a9aca9fdd4dcc13fe497cabdb13ca1e5d6a529271c8aa495e5ca1c1c80271ec"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $aspxauth = ".ASPXAUTH" ascii wide nocase
        $panel_lateral = "Panel-Lateral" ascii wide
        $toolbox_relay = "ToolboxRelayUploader" ascii wide
        $page_service = "PageService.ashx" ascii wide
        $get_access_token = "GetAccessToken" ascii wide
        $get_live_data = "GetLiveData" ascii wide
        $add_session_events = "AddSessionEvents" ascii wide
        $open_process = "OpenProcess" ascii wide
        $read_process_memory = "ReadProcessMemory" ascii wide
        $virtual_query = "VirtualQueryEx" ascii wide
        $network_mojom = "network.mojom.NetworkService" ascii wide
        $shared_toolbox = "SharedToolbox" ascii wide

    condition:
        filesize < 5MB and
        (
            ($aspxauth and $panel_lateral) or
            ($aspxauth and 2 of ($page_service, $get_access_token, $get_live_data, $add_session_events)) or
            ($open_process and $read_process_memory and $virtual_query and $network_mojom) or
            ($shared_toolbox and $toolbox_relay and $aspxauth) or
            5 of them
        )
}
