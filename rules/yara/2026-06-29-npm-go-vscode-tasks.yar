rule Malware_ContagiousInterview_VSCode_Tasks_FolderOpen
{
    meta:
        description = "Detects malicious VS Code tasks.json with folderOpen auto-execution used by Contagious Interview campaign to deploy InvisibleFerret"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $tasks_ver = "\"version\"" ascii
        $run_on = "folderOpen" ascii
        $run_opts = "runOptions" ascii

        $cmd_woff2 = ".woff2" ascii
        $cmd_curl_sh = "| sh" ascii
        $cmd_curl = "curl" ascii
        $cmd_node = "node " ascii

        $label_eslint = "eslint-check" ascii
        $label_env = "\"label\": \"env\"" ascii nocase

        $font_fa_solid = "fa-solid-400.woff2" ascii
        $font_fa_brands = "fa-brands-regular.woff2" ascii

    condition:
        filesize < 10KB and
        $tasks_ver and $run_on and $run_opts and
        (
            1 of ($font_fa*) or
            $label_eslint or
            ($cmd_woff2 and ($cmd_node or $cmd_curl)) or
            ($label_env and ($cmd_woff2 or 1 of ($font_fa*) or $label_eslint)) or
            ($cmd_curl_sh and ($cmd_woff2 or 1 of ($font_fa*) or $label_eslint))
        )
}

rule Malware_InvisibleFerret_Python_Infostealer
{
    meta:
        description = "Detects the InvisibleFerret Python infostealer deployed by Contagious Interview campaign via hijacked npm/Go packages"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/"
        hash = "ef12b15466255fafda6225a557cce780baa6b1c98adcf111f5564e7b3ecc0e14"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $s_chrome_login = "Login Data" ascii wide
        $s_chrome_cookies = "Cookies" ascii wide
        $s_firefox_logins = "logins.json" ascii wide
        $s_keychain = "security find-generic-password" ascii
        $s_credential_mgr = "Windows Credential Manager" ascii wide
        $s_secret_service = "Secret Service" ascii
        $s_kde_wallet = "KDE Wallet" ascii

        $wallet_metamask = "MetaMask" ascii wide
        $wallet_phantom = "Phantom" ascii wide
        $wallet_tronlink = "TronLink" ascii wide
        $wallet_exodus = "Exodus" ascii wide

        $dev_git_cred = ".git-credentials" ascii
        $dev_gh_hosts = "hosts.yml" ascii
        $dev_gh_desktop = "GitHub Desktop" ascii wide
        $dev_vscode = "globalStorage" ascii

        $cloud_dropbox = "Dropbox" ascii wide
        $cloud_gdrive = "Google Drive" ascii wide
        $cloud_onedrive = "OneDrive" ascii wide
        $cloud_icloud = "iCloud" ascii wide

        $exfil_telegram = "api.telegram.org" ascii
        $exfil_zip = "zipfile" ascii
        $exfil_upload = "/u/f" ascii
        $exfil_env = "/snv" ascii

    condition:
        filesize < 5MB and
        (
            (3 of ($s_*) and 2 of ($wallet_*) and 1 of ($dev_*)) or
            (2 of ($s_*) and 1 of ($cloud_*) and $exfil_telegram) or
            (4 of ($s_*) and ($exfil_upload or $exfil_env)) or
            ($exfil_zip and $exfil_telegram and 2 of ($s_*))
        )
}

rule Malware_ContagiousInterview_FakeFont_JS_Payload
{
    meta:
        description = "Detects JavaScript payload disguised as font file (.woff2) used by Contagious Interview Fake Font variant to bootstrap blockchain dead-drop resolver"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $trongrid = "api.trongrid.io" ascii
        $aptos = "aptoslabs.com" ascii
        $bsc_data = "bsc-dataseed.binance.org" ascii
        $bsc_rpc = "bsc-rpc.publicnode.com" ascii

        $tron_addr1 = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" ascii
        $tron_addr2 = "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG" ascii
        $tron_addr3 = "TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v" ascii

        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "ThZG+0jfXE6VAGOJ" ascii

        $eval_call = "eval(" ascii
        $socket_io = "socket.io" ascii
        $sec_v = "Sec-V" ascii

    condition:
        filesize < 1MB and
        (
            (1 of ($trongrid, $aptos, $bsc_data, $bsc_rpc) and 1 of ($tron_addr*)) or
            (1 of ($xor_key*) and $eval_call) or
            (1 of ($trongrid, $aptos) and $socket_io) or
            (1 of ($tron_addr*) and $sec_v)
        )
}
