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
