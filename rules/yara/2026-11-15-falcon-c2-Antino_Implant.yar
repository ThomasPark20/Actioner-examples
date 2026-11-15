rule Antino_Implant
{
    meta:
        description = "Detects the Antino implant used alongside Falcon C2, a Rust-compiled backdoor using OneDrive for C2"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/"
        hash = "0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd"

    strings:
        $path_heartbeat = "antino/heartbeat/" ascii wide
        $path_upload = "antino/antino_upload/" ascii wide
        $cmd_req = "command_req_" ascii wide
        $dir_gather = "Windows GatherOSStateKit" ascii wide
        $cfg_section = ".cfg" ascii
        $cmd1 = "system_info" ascii wide
        $cmd2 = "list_files" ascii wide
        $cmd3 = "add_to_run" ascii wide
        $cmd4 = "execute_program" ascii wide
        $cmd5 = "upload_file" ascii wide
        $cmd6 = "download_file" ascii wide
        $dll1 = "DllSafeCheck64.dll" ascii wide
        $dll2 = "slc.dll" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($path_heartbeat and $path_upload) or
            ($cmd_req and $dir_gather) or
            ($cfg_section and 3 of ($cmd*)) or
            ($dll1 and $dll2 and 2 of ($cmd*))
        )
}
