// DOUBLECUP / CountLoader / DeviceManager RAT - YARA Detection Rules
// Date: 2026-08-07
// Reference: https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/
// Version: 1.0

rule Malware_DOUBLECUP_Steganographic_PNG_Marker
{
    meta:
        description = "Detects steganographic PNG files used by DOUBLECUP loader containing the ZZ1984 extraction marker string"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
        $marker = "ZZ1984" ascii

    condition:
        $png_header at 0 and
        $marker and
        filesize < 5MB
}

rule Malware_CountLoader_45p_Windows
{
    meta:
        description = "Detects CountLoader 4.5p Windows PowerShell variant via campaign tracking key, version string, and characteristic C2 parameters"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "bdf28e611d77362c40a0445655a35943c03accf21bb9a5af755da7eac5ea5e40"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $key = "K94DGQ99VYCCH52TKOT2" ascii wide
        $ver = "4.5p" ascii wide
        $c2_connect = "/connect" ascii wide
        $c2_updates = "/getUpdates" ascii wide
        $c2_approve = "/approveUpdate" ascii wide
        $xor_63 = "-bxor 63" ascii wide nocase
        $python_embed = "python-3.13.13-embed-amd64" ascii wide
        $irm_iex = "irm" ascii wide
        $schtask_google = "GoogleUpdateService" ascii wide
        $schtask_edge = "MSEdgeUpdateService" ascii wide

    condition:
        (3 of ($key, $ver, $c2_*)) or
        ($key and 2 of ($xor_63, $python_embed, $irm_iex)) or
        ($key and any of ($schtask_*))
}

rule Malware_DeviceManager_RAT
{
    meta:
        description = "Detects DeviceManager RAT Python source or compiled variant via characteristic blockchain C2 resolution, DNS tunneling, and configuration artifacts"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "ea70895620f955b0712b85c3fee41de7437d5068267966f0b4fb6fa2704c3a50"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $contract = "0xc027490AF56a9d7050fc259Ecd03DA1580b84aae" ascii wide nocase
        $eth_addr = "0xCE17b1EF00d47105Bc127BbE6fC45dE47BC22fb8" ascii wide nocase
        $func_sel_get = "0x1dcf296b" ascii wide
        $func_sel_upd = "0xc474520d" ascii wide
        $func_sel_tgt = "0x71c28139" ascii wide
        $dns_spoof = ".microsoft.com" ascii wide
        $task_name = "MicroUpdaterV1" ascii wide
        $wmi_filter = "PythonAppUpdateFilter" ascii wide
        $wmi_consumer = "PythonAppUpdateConsumer" ascii wide
        $wmi_timer = "PythonAppTimer_600" ascii wide
        $config_path = "DeviceManager" ascii wide
        $agent_log = "agent.log" ascii wide
        $agent_main = "agent_main.pyw" ascii wide
        $blockchain_key = "blockchain_key" ascii wide
        $chacha20 = "ChaCha20" ascii wide nocase

    condition:
        any of ($contract, $eth_addr) or
        (2 of ($func_sel_*)) or
        ($task_name and 2 of ($wmi_*, $config_path, $agent_*, $blockchain_key, $chacha20)) or
        ($dns_spoof and $blockchain_key and any of ($agent_*))
}

rule Malware_DeviceManager_InnoSetup_Installer
{
    meta:
        description = "Detects the DeviceManager RAT Delphi-compiled Inno Setup installer via characteristic IPC flag pattern and installation paths"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "6e08cb5602f63bee2b40739167b4aef77763bc8fb47b4839ca2fc1607ad35cba"
        severity = "high"
        tlp = "WHITE"

    strings:
        $inno_ipc = "/SL5=" ascii wide
        $python_app = "Microsoft.PythonApp_yadfiy2x1ep12" ascii wide
        $run_pyw = "run.pyw" ascii wide
        $micro_updater = "MicroUpdaterV1" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        ($python_app or
        ($inno_ipc and $run_pyw and $micro_updater))
}

rule Malware_DOUBLECUP_Client_Agent
{
    meta:
        description = "Detects the DOUBLECUP client agent used by operators to manage ClickFix campaigns and payload delivery"
        author = "Actioner"
        date = "2026-08-07"
        reference = "https://socradar.io/blog/doublecup-clickfix-loader-devicemanager-rats/"
        hash = "882914f9014f14e89123e835f103ac8f9d4b2e358c1f21c1cbc7f1054e6afed6"
        severity = "high"
        tlp = "WHITE"

    strings:
        $session_reg = "/session/reg" ascii wide
        $session_check = "/session/check" ascii wide
        $session_signal = "/session/signal" ascii wide
        $api_config = "/api/config" ascii wide
        $stego_image = "stego-image" ascii wide

    condition:
        (uint16(0) == 0x5A4D and 3 of ($session_*, $api_config, $stego_image)) or
        ($stego_image and 2 of ($session_*))
}
