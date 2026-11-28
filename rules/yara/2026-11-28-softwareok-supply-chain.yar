rule SoftwareOK_SupplyChain_TrojanizedInstaller
{
    meta:
        description = "Detects trojanized Q-Dir or DesktopOK installers from the SoftwareOK supply chain attack (Nov 2026)"
        author = "Actioner Detection Engineering"
        date = "2026-11-28"
        reference = "https://asec.ahnlab.com/en/96827/"
        hash1 = "434b67dd403c74752b336fbb4fc94ee3a6fb615168e3fd31baea71d1a356ecd8"
        hash2 = "1b7b7947527a05f0fae268b16894440549c2dd512d421a06960e27b5fb1d5fa0"
        hash3 = "551e5744b24019f016f9ee8dd3a2c00429da587b20321abaef55c18c0a655a5d"
        hash4 = "5b43284e48edee4acbab49bc5a68eb21d3a369a058d859689b6a5dd2042a5e2a"
        hash5 = "393d2f9f05affa88aaa19f29f041d28fe5c3e1fc2fd84c76d1e2f1aa6da74a83"

    strings:
        $payload_archive = "dsv2_py39_agent.7z" ascii wide
        $rat_script = "py_client_dsv2.py" ascii wide
        $c2_domain = "mail.c1a2.top" ascii wide
        $download_path = "/dl/7zr.exe" ascii wide
        $download_path2 = "/dl/dsv2_py39_agent" ascii wide
        $schtask_name = "MicrosoftEdge_dcntel" ascii wide
        $install_path1 = "\\Microsoft\\DeviceSync\\b2" ascii wide
        $install_path2 = "\\DeviceSync\\b2" ascii wide
        $pythonw_agent = "pythonw.exe" ascii wide

        $qdir_ref = "Q-Dir" ascii wide
        $desktopok_ref = "DesktopOK" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and
        (
            ($payload_archive and $rat_script) or
            ($c2_domain) or
            ($schtask_name and ($install_path1 or $install_path2)) or
            ($download_path and $download_path2) or
            (($qdir_ref or $desktopok_ref) and $rat_script and $pythonw_agent)
        )
}

rule SoftwareOK_SupplyChain_PythonRAT_Agent
{
    meta:
        description = "Detects the Python RAT agent script (py_client_dsv2) used in the SoftwareOK supply chain attack"
        author = "Actioner Detection Engineering"
        date = "2026-11-28"
        reference = "https://asec.ahnlab.com/en/96827/"

    strings:
        $script_name = "py_client_dsv2" ascii
        $c2_ip = "8.210.69.51" ascii
        $c2_port = "9876" ascii
        $func_shell = "shell" ascii
        $func_screenshot = "screenshot" ascii
        $func_upload = "upload" ascii
        $func_download = "download" ascii
        $func_sysinfo = "sysinfo" ascii
        $sec_crowdstrike = "CrowdStrike" ascii
        $sec_sentinelone = "SentinelOne" ascii
        $sec_ahnlab = "AhnLab" ascii

    condition:
        filesize < 5MB and
        (
            ($script_name and $c2_ip) or
            ($script_name and $c2_port and 2 of ($func_*)) or
            ($c2_ip and $c2_port and 2 of ($sec_*))
        )
}

rule SoftwareOK_SupplyChain_RAT_Archive
{
    meta:
        description = "Detects the dsv2_py39_agent.7z archive containing the Python RAT payload"
        author = "Actioner Detection Engineering"
        date = "2026-11-28"
        reference = "https://asec.ahnlab.com/en/96827/"

    strings:
        $7z_header = { 37 7A BC AF 27 1C }
        $rat_path1 = "py39/agent/py_client_dsv2.py" ascii
        $rat_path2 = "py39\\agent\\py_client_dsv2.py" ascii
        $pythonw = "pythonw.exe" ascii

    condition:
        $7z_header at 0 and filesize < 100MB and
        ($rat_path1 or $rat_path2) and $pythonw
}
