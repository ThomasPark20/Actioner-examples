rule Malware_macOS_Reaper_SHub_Stealer
{
    meta:
        description = "Detects the Reaper (SHub) macOS infostealer via distinctive strings found in AppleScript payloads and shell scripts including staging paths, C2 endpoints, and build identifiers"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $c2_domain = "hebsbsbzjsjshduxbs.xyz" ascii wide
        $c2_gate = "/gate/chunk" ascii
        $c2_heartbeat = "/api/bot/heartbeat" ascii
        $c2_debug = "/api/debug/event" ascii

        $staging_dir = "/tmp/shub_" ascii
        $split_script = "shub_split.sh" ascii
        $mzip = "shub_mzip_" ascii

        $build_hash = "c917fcf8314228862571f80c9e4a871e" ascii

        $persistence_path = "Google/GoogleUpdate.app/Contents/MacOS/GoogleUpdate" ascii
        $plist_name = "com.google.keystone.agent.plist" ascii

        $wallet_exodus = "exodus_asar.zip" ascii
        $wallet_inject = "_asar.zip" ascii

        $cis_check = "cis_blocked" ascii
        $hidden_script = "/tmp/.c.sh" ascii

        $lure_domain1 = "mlcrosoft.co.com" ascii
        $lure_domain2 = "mlroweb.com" ascii

    condition:
        filesize < 10MB and
        (
            ($c2_domain and 1 of ($c2_gate, $c2_heartbeat, $c2_debug)) or
            ($build_hash) or
            (2 of ($staging_dir, $split_script, $mzip)) or
            ($persistence_path and $plist_name) or
            (3 of them)
        )
}

rule Malware_macOS_Reaper_AppleScript_Payload
{
    meta:
        description = "Detects Reaper macOS stealer AppleScript payloads that use the applescript:// URL scheme with XProtectRemediator spoofing and obfuscated Script Editor content"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://www.sentinelone.com/blog/shub-reaper-macos-stealer-spoofs-apple-google-and-microsoft-in-a-single-attack-chain/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $scheme = "applescript://" ascii
        $xprotect_spoof = "XProtectRemediator" ascii nocase
        $script_editor = "Script Editor" ascii
        $curl_cmd = "curl" ascii
        $do_shell = "do shell script" ascii

        $c2 = "hebsbsbzjsjshduxbs.xyz" ascii
        $fake_apple = "support.apple.com/downloads/xprotect-remediator" ascii

    condition:
        filesize < 5MB and
        (
            ($scheme and $xprotect_spoof) or
            ($do_shell and $c2) or
            ($fake_apple and ($curl_cmd or $do_shell)) or
            ($scheme and $do_shell and $curl_cmd and 1 of ($c2, $fake_apple, $xprotect_spoof)) or
            ($script_editor and $do_shell and $xprotect_spoof)
        )
}
