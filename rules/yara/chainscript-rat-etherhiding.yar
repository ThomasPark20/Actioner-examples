rule ChainScript_RAT_Agent_Source
{
    meta:
        description = "Detects ChainScript RAT Node.js agent source code by matching key function names, WebSocket protocol strings, and EtherHiding contract discovery patterns"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/"
        hash1 = "20a9e297220fe4cb9f939eaa82582c6e9a8f6dd4424635206dec08fa1986b8fa"

    strings:
        $ws_token = "X-Agent-Token" ascii wide
        $func_selector = "0x4ab7874e" ascii wide
        $eth_call = "eth_call" ascii wide
        $wallet_scan = "wallet_scan" ascii wide
        $agent_update = "agent_update" ascii wide
        $download_run = "download_run" ascii wide
        $heartbeat = "heartbeat" ascii wide
        $extra_commands = "extraCommands" ascii wide
        $contract_addr = "0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4" ascii wide nocase
        $build_seed = "buildSeed" ascii wide
        $scatter = "._scatter.ps1" ascii wide
        $agent_vbs = "._agent.vbs" ascii wide
        $config_file = "HiddenVirtualSilentLoader.dat" ascii wide

    condition:
        3 of ($ws_token, $func_selector, $eth_call, $contract_addr) or
        4 of ($wallet_scan, $agent_update, $download_run, $heartbeat, $extra_commands, $build_seed) or
        2 of ($scatter, $agent_vbs, $config_file)
}

rule ChainScript_Config_BuildDescriptor
{
    meta:
        description = "Detects ChainScript RAT configuration templates and build descriptor files by matching JSON keys used in the packed configuration and install metadata"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/"

    strings:
        $key1 = "buildSeed" ascii wide
        $key2 = "heartbeatIntervalMs" ascii wide
        $key3 = "reconnectDelayMs" ascii wide
        $key4 = "contractDiscovery" ascii wide
        $key5 = "panelUrl" ascii wide
        $key6 = "cacheTtlMs" ascii wide
        $key7 = "scatter-layout" ascii wide
        $key8 = "contract-discovery" ascii wide
        $key9 = "build-polymorph" ascii wide
        $key10 = "packed-config" ascii wide
        $key11 = "wallet-scan-manual" ascii wide

    condition:
        4 of them
}

rule ChainScript_DotNet_Helpers
{
    meta:
        description = "Detects ChainScript RAT .NET helper executables (ProfileQuickHost launcher and SearchTrustedRuntimeSvc screenshot tool) by MVID and PE characteristics"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://github.com/Justice-Hammer/threat-hunting-detections/blob/main/30-research/RES-0007%20-%20ComponentTask33%20MSI%20Loader%20with%20On-Chain%20C2%20Discovery.md"
        hash1 = "9fa80577b8b3cb9c3062e5e1986cc9fe0c26eed023f7d430dfa5c60169c15c45"
        hash2 = "7969ccaf1db750bc3b02d51626d6916ecbd0c0cf2f7de3c7bc0be240f5f2978d"

    strings:
        $mvid1 = { 9B 0E 9F C0 41 15 53 45 85 8F 40 5D 8C 8C A2 97 }
        $mvid2 = { 31 45 8E 5C 34 C3 10 4E B3 89 48 1F 7A 12 AD E3 }
        $name1 = "ProfileQuickHost" ascii wide
        $name2 = "SearchTrustedRuntimeSvc" ascii wide
        $pe_magic = { 4D 5A }

    condition:
        $pe_magic at 0 and (any of ($mvid*) or any of ($name*))
}

rule ChainScript_MSI_Dropper
{
    meta:
        description = "Detects ChainScript RAT MSI dropper files by matching known MSI GUIDs, embedded file references, and build artifacts from the Windows Installer XML Toolset"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blackpointcyber.com/blog/chainscript-tracing-a-nodejs-rat-across-the-blockchain/"
        hash1 = "20a9e297220fe4cb9f939eaa82582c6e9a8f6dd4424635206dec08fa1986b8fa"
        hash2 = "6e07d2de3618bb92265248653361ff39c63c0cfba2f4aa2538b3128fa9ce3a50"
        hash3 = "bad0600a850436154f8d7b6f7a191dc45bd136897780cd032b336cb4b358d241"
        hash4 = "496c202abf53984164f5f319a72b02c8e06016d0f35681353ef07db8e6d1b31f"

    strings:
        $guid_upgrade = "F22A91B0-7A00-4C4D-A9AC-0DE43E0BD888" ascii wide nocase
        $guid_product = "DBC7258E-9E9F-4064-8B65-BFEDEF7DC170" ascii wide nocase
        $file_scatter = "._scatter.ps1" ascii wide
        $file_agent = "._agent.vbs" ascii wide
        $file_config = "HiddenVirtualSilentLoader.dat" ascii wide
        $file_meta = "install-meta.json" ascii wide
        $msi_magic = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $msi_magic at 0 and (any of ($guid*) or 2 of ($file*))
}
