rule MAL_PostCSS_RAT_PYD_Modules
{
    meta:
        description = "Detects Nuitka-compiled Python .pyd modules associated with the PostCSS npm supply chain RAT"
        author = "Actioner DRAFT"
        date = "2026-06-25"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"
        hash1 = "164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3"
        hash2 = "50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf"
        hash3 = "17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871"
        hash4 = "c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2"
        hash5 = "f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798"
        hash6 = "282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990"

    strings:
        $pyd_audio = "audiodriver.cp310-win_amd64.pyd" ascii wide
        $pyd_api = "api.cp310-win_amd64.pyd" ascii wide
        $pyd_auto = "auto.cp310-win_amd64.pyd" ascii wide
        $pyd_cmd = "command.cp310-win_amd64.pyd" ascii wide
        $pyd_cfg = "config.cp310-win_amd64.pyd" ascii wide
        $pyd_util = "util.cp310-win_amd64.pyd" ascii wide

        $c2_ip = "95.216.92.207" ascii wide
        $c2_port = ":8080" ascii wide
        $c2_domain = "nvidiadriver.net" ascii wide

        $reg_key = "csshost" ascii wide
        $chrome_query = "SELECT origin_url, username_value, password_value" ascii wide
        $chrome_key = "Google Chromekey1" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($pyd_*) or
            ($c2_ip and $c2_port) or
            ($c2_domain) or
            ($reg_key and $chrome_query) or
            ($chrome_key and any of ($c2_*))
        )
}

rule MAL_PostCSS_NPM_Dropper_JS
{
    meta:
        description = "Detects the JavaScript dropper payload from malicious PostCSS npm packages"
        author = "Actioner DRAFT"
        date = "2026-06-25"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"

    strings:
        $s1 = "settings.ps1" ascii
        $s2 = "nvidiadriver.net" ascii
        $s3 = "winpatch" ascii nocase
        $s4 = "AES-256-GCM" ascii
        $s5 = "postcss-minify-selector" ascii

        $enc1 = "createDecipheriv" ascii
        $enc2 = "aes-256-gcm" ascii

        $exec1 = "child_process" ascii
        $exec2 = "execSync" ascii

    condition:
        (
            ($s1 and $s2) or
            ($s5 and any of ($enc*)) or
            ($s3 and $s4 and any of ($exec*))
        )
}

rule MAL_PostCSS_RAT_Chrome_Stealer
{
    meta:
        description = "Detects the Chrome credential theft module (auto.pyd) from the PostCSS RAT"
        author = "Actioner DRAFT"
        date = "2026-06-25"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"
        hash = "17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871"

    strings:
        $chrome1 = "Login Data" ascii wide
        $chrome2 = "chrome_logins_dump" ascii wide
        $chrome3 = "Google Chromekey1" ascii wide
        $chrome4 = "pwd.txt" ascii wide
        $chrome5 = "gather.tar.gz" ascii wide

        $api1 = "NCryptOpenStorageProvider" ascii wide
        $api2 = "NCryptOpenKey" ascii wide
        $api3 = "NCryptDecrypt" ascii wide

        $crypto1 = "ChaCha20_Poly1305" ascii wide
        $crypto2 = "AES" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($chrome*) and any of ($api*)) or
            ($chrome2 and $chrome4 and $chrome5) or
            (all of ($api*) and any of ($chrome*)) or
            (any of ($crypto*) and 2 of ($chrome*))
        )
}

rule MAL_PostCSS_RAT_Settings_PS1
{
    meta:
        description = "Detects the PowerShell dropper script (settings.ps1) used in the PostCSS supply chain attack"
        author = "Actioner DRAFT"
        date = "2026-06-25"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"

    strings:
        $url = "nvidiadriver.net" ascii
        $dl_path = "winPatch.zip" ascii
        $expand = "Expand-Archive" ascii
        $curl = "curl.exe" ascii
        $vbs = "update.vbs" ascii
        $wscript = "wscript" ascii

    condition:
        3 of them
}
