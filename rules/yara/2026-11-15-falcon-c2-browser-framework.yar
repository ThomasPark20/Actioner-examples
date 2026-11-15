rule Falcon_C2_Browser_Extension_Manifest
{
    meta:
        description = "Detects Falcon C2 malicious browser extension manifest disguised as PDF Viewer"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/"
        hash = "b6a7be724871ed3e81c986b74d62da8911c82a336c4c1857b35f2446b2d49fda"

    strings:
        $ext_name = "PDF Viewer" ascii wide
        $ext_desc = "Portable Document Format" ascii wide
        $ext_version = "2026.5.13.1" ascii wide
        $ext_id = "mbidcmlcbgbphpoacojjbmfpohcimjji" ascii wide
        $file_analytics = "analytics-core.js" ascii wide
        $file_twitter = "twitter-dm.js" ascii wide
        $file_sandbox = "sandbox.html" ascii wide
        $file_offscreen = "offscreen.js" ascii wide
        $all_urls = "<all_urls>" ascii wide

    condition:
        ($ext_id) or
        ($ext_name and $ext_desc and $ext_version) or
        ($ext_name and $all_urls and 3 of ($file_*))
}

rule Falcon_C2_JavaScript_Implant
{
    meta:
        description = "Detects Falcon C2 JavaScript implant code patterns including C2 functions and storage keys"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/"

    strings:
        $func_xg_note = "xg_note" ascii wide
        $func_xg_send = "xg_send" ascii wide
        $func_xg_data = "xg_data" ascii wide
        $func_xg_notify = "xg_notify" ascii wide
        $func_proxy = "handleProxyRequest" ascii wide
        $func_storage = "storageApi" ascii wide
        $storage_hmvlt = "Hm_lvt_" ascii wide
        $storage_remark = "_domain_google_mark" ascii wide
        $storage_clipboard = "clipboard_replacer_rules" ascii wide
        $action_pubkey = "pubkey" ascii wide
        $action_key_exchange = "key_exchange" ascii wide

    condition:
        3 of ($func_*) or
        ($storage_hmvlt and $storage_remark) or
        ($func_xg_send and $action_key_exchange) or
        ($storage_clipboard and $storage_hmvlt and $func_xg_send) or
        ($action_pubkey and $action_key_exchange and $func_xg_send)
}

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
