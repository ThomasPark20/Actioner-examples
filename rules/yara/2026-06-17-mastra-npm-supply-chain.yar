rule easy_day_js_stage1_dropper {
    meta:
        description = "Detects the easy-day-js stage-1 dropper (setup.cjs) used in the Mastra npm supply chain attack"
        author = "Actioner CTI"
        date = "2026-06-17"
        reference = "https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/"
        hash = "4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417"
        severity = "critical"

    strings:
        $postinstall = "postinstall" ascii
        $setup_cjs = "setup.cjs" ascii
        $tls_disable = "NODE_TLS_REJECT_UNAUTHORIZED" ascii
        $self_delete = "rmSync(__filename" ascii
        $detach = "\"detached\":true" ascii nocase
        $detach2 = "detached: true" ascii nocase
        $stdio_ignore = "stdio" ascii
        $windows_hide = "windowsHide" ascii
        $c2_ip1 = "23.254.164.92" ascii
        $c2_ip2 = "23.254.164.123" ascii
        $campaign_id = "49890878" ascii
        $update_path = "/update/49890878" ascii
        $xor_bytes = { e5 e1 f3 f9 ad e4 e1 f9 ad ea f3 }
        $pkg_history = ".pkg_history" ascii
        $pkg_logs = ".pkg_logs" ascii

    condition:
        filesize < 50KB and (
            ($c2_ip1 or $c2_ip2 or $update_path) or
            ($xor_bytes) or
            ($tls_disable and $self_delete and ($detach or $detach2)) or
            ($pkg_history and $pkg_logs and $setup_cjs) or
            (4 of ($postinstall, $setup_cjs, $self_delete, $stdio_ignore, $windows_hide, $campaign_id))
        )
}

rule easy_day_js_stage2_rat {
    meta:
        description = "Detects the easy-day-js stage-2 RAT payload used in the Mastra npm supply chain attack"
        author = "Actioner CTI"
        date = "2026-06-17"
        reference = "https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/"
        hash = "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf"
        severity = "critical"

    strings:
        $c2_ip = "23.254.164.123" ascii
        $campaign_id = "49890878" ascii
        $beacon_type = "\"type\":\"prepare\"" ascii nocase
        $beacon_type2 = "\"type\": \"prepare\"" ascii nocase
        $target_id = "targetId" ascii
        $common_info = "\"common\"" ascii
        $app_info = "\"appInfo\"" ascii
        $ext_info = "\"extInfo\"" ascii
        $cmd_tag = "tpcsr" ascii
        $resp_tag = "\"r0\"" ascii
        $plist_persist = "com.nvm.protocal.plist" ascii
        $protocal_cjs = "protocal.cjs" ascii
        $nvmconf_service = "nvmconf.service" ascii
        $node_packages = "NodePackages" ascii
        $metamask = "MetaMask" ascii
        $phantom = "Phantom" ascii
        $solflare = "Solflare" ascii
        $wolfssl_cn = "www.wolfssl.com" ascii

    condition:
        filesize < 500KB and (
            ($c2_ip and $campaign_id) or
            ($plist_persist and $node_packages) or
            ($nvmconf_service and $node_packages) or
            ($cmd_tag and $resp_tag) or
            (($beacon_type or $beacon_type2) and ($target_id and $common_info and $app_info and $ext_info)) or
            (3 of ($protocal_cjs, $node_packages, $metamask, $phantom, $solflare, $wolfssl_cn))
        )
}

rule easy_day_js_persistence_artifacts {
    meta:
        description = "Detects persistence artifacts written by the easy-day-js RAT on disk"
        author = "Actioner CTI"
        date = "2026-06-17"
        reference = "https://safedep.io/mastra-npm-scope-takeover-supply-chain-attack/"
        severity = "high"

    strings:
        $plist_name = "com.nvm.protocal" ascii
        $protocal_path = "Library/NodePackages/protocal.cjs" ascii
        $systemd_name = "nvmconf.service" ascii
        $config_node = "NodePackages/config.json" ascii
        $execution_bypass = "ExecutionPolicy Bypass" ascii nocase

    condition:
        2 of them
}
