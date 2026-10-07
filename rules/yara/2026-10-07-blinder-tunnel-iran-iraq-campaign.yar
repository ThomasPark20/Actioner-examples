rule APT_CL_STA_1178_ShelbyLoader_V2 : BlinderTunnel
{
    meta:
        description = "Detects ShelbyLoader V2 (RuntimeBroker.dll) used in the Blinder Tunnel campaign (CL-STA-1178) via characteristic strings and configuration patterns"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
        hash = "53f35e49eb9b271fd8cbcd3daacb525328dbf159a03dbd1c7adebe0363daa402"
        severity = "high"

    strings:
        $gh_repo = "peakyblinders-tm/myLic" ascii wide
        $gh_token = "github_pat_11B2HDA2Q0KDdo" ascii wide
        $machid_seed = "Peaky Blinders 2.1" ascii wide
        $file_lic = "/Lic.txt" ascii wide
        $file_inf = "/Inf.txt" ascii wide
        $persist_key = "MicrosoftRuntime" ascii wide
        $path_brokers = "RuntimeBrokers" ascii wide
        $cfg_etw = "etwEnable" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        4 of them
}

rule APT_CL_STA_1178_Blackwood_Tunneler : BlinderTunnel
{
    meta:
        description = "Detects the Blackwood custom Chisel tunneling wrapper used by the Blinder Tunnel campaign (CL-STA-1178)"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
        hash = "76273382e4252c1f60a2251141e108942494409c759358320735891762c0682e"
        severity = "high"

    strings:
        $passphrase = "y0Da+QH#pwSg38E?=8R;71-jQu8Tqq" ascii wide
        $rc4_key = "My name is Blackwood !" ascii wide
        $manifest = "Blackwood.Cheese.xml" ascii wide
        $socks_cfg = "R:0.0.0.0:10999:socks" ascii wide
        $conf_name = "Blackwood.dll.conf" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        2 of them
}

rule APT_CL_STA_1178_PsProxy : BlinderTunnel
{
    meta:
        description = "Detects PsProxy.dll in-memory PowerShell execution engine used by the Blinder Tunnel campaign (CL-STA-1178)"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
        hash = "3fd810a3aa0039993393741b32287c367a9a5037a41e826906440887cdd3ed13"
        severity = "high"

    strings:
        $ps_auto = "System.Management.Automation" ascii wide
        $ps_runspace = "RunspaceFactory" ascii wide
        $ps_invoke = "Invoke" ascii wide
        $shelby_ref = "RuntimeBrokerApi" ascii wide
        $shelby_ref2 = "ShelbyC2" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        ($ps_auto and $ps_runspace and $ps_invoke) and
        1 of ($shelby*)
}

rule APT_CL_STA_1178_Trojanized_CSProj : BlinderTunnel
{
    meta:
        description = "Detects trojanized Visual Studio C# project files used as initial access in the Blinder Tunnel campaign (CL-STA-1178)"
        author = "Actioner"
        date = "2026-10-07"
        reference = "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
        hash = "f5b12772db6817f7a765a6fe7565fd3d4f87edc28e42fe3ec0244a372a410fc9"
        severity = "high"

    strings:
        $target_override = "GetFrameworkPaths" ascii wide
        $runtime_brokers = "RuntimeBrokers" ascii wide
        $runtime_broker_exe = "RuntimeBroker.exe" ascii wide
        $xml_target = "<Target" ascii
        $xml_copy = "<Copy" ascii

    condition:
        filesize < 500KB and
        $target_override and
        ($runtime_brokers or $runtime_broker_exe) and
        ($xml_target and $xml_copy)
}
