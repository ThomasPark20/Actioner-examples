rule PostCSS_Lookalike_RAT_PYD_Modules
{
    meta:
        description = "Detects compiled Python modules (.pyd) associated with the PostCSS lookalike npm supply chain RAT"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"
        hash = "164e322d6fbc62e254d73583acd7f39444c884d3f5e6a5d27db143fc25bc88b3"
        hash = "50ffce607867d8fa8eaf6ef5cd25a3c0e7e4415e881b9e55c04a67bcddb74fdf"
        hash = "17832aa629524ef6e8d8d6e9b6b902a8d324b559e3c36dbd0e221ab1690be871"
        hash = "c8075bbff748096e1c6a1ea0aa67bb6762fdd7551427a12425b35b94c1f1ecf2"
        hash = "f6669bd504ce6b0e303be7ee47f2ebbc062989c88c41f0a3f436044a24869798"
        hash = "282b9bc318ad1234cbd1b86424b784299b8be31545802a7c6b751166b814b990"

    strings:
        $pyd_audiodriver = "audiodriver.cp310-win_amd64" ascii wide
        $pyd_api = "api.cp310-win_amd64" ascii wide
        $pyd_auto = "auto.cp310-win_amd64" ascii wide
        $pyd_command = "command.cp310-win_amd64" ascii wide
        $pyd_config = "config.cp310-win_amd64" ascii wide
        $pyd_util = "util.cp310-win_amd64" ascii wide
        $loader = "loader.py" ascii wide
        $chost = "chost.exe" ascii wide
        $c2_ip = "95.216.92.207" ascii wide
        $c2_domain = "nvidiadriver.net" ascii wide
        $reg_key = "csshost" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($pyd_*) and ($c2_ip or $c2_domain) or
            3 of ($pyd_*) or
            ($chost and $loader and $reg_key)
        )
}

rule PostCSS_Lookalike_RAT_JS_Dropper
{
    meta:
        description = "Detects the JavaScript dropper embedded in malicious PostCSS npm packages"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"
        // hash omitted — no confirmed SHA-256 for the JS dropper file itself

    strings:
        $settings_ps1 = "settings.ps1" ascii
        $aes_gcm = "aes-256-gcm" ascii nocase
        $nvidiadriver = "nvidiadriver" ascii nocase
        $winpatch = "winpatch" ascii nocase
        $winPatch_zip = "winPatch.zip" ascii
        $curl_download = "curl.exe" ascii
        $expand_archive = "Expand-Archive" ascii

    condition:
        filesize < 500KB and
        (
            ($settings_ps1 and $aes_gcm) or
            ($nvidiadriver and $winpatch) or
            ($curl_download and $winPatch_zip and $expand_archive)
        )
}

rule PostCSS_Lookalike_RAT_VBS_Bootstrap
{
    meta:
        description = "Detects the VBScript bootstrapper (update.vbs) used by the PostCSS lookalike npm RAT"
        author = "Actioner"
        date = "2026-06-24"
        reference = "https://research.jfrog.com/post/from-postcss-typosquat-to-windows-rat/"
        // hash omitted — no confirmed SHA-256 for update.vbs itself

    strings:
        $chost = "chost.exe" ascii wide nocase
        $loader = "loader.py" ascii wide nocase
        $wscript_shell = "WScript.Shell" ascii nocase
        $winpatch = "winPatch" ascii

    condition:
        filesize < 50KB and
        (
            ($chost and $loader) or
            ($wscript_shell and $winpatch and ($chost or $loader))
        )
}
