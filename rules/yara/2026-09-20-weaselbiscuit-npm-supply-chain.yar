rule WeaselBiscuit_JS_Stealer
{
    meta:
        description = "Detects WeaselBiscuit JavaScript stealer payload strings — npm supply-chain campaign targeting Chrome extension storage"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://opensourcemalware.com/blog/introducing-weaselbiscuit"
        hash = "7b15605f23b131b3eeea57e031ae7cb32fc4b78c7bbb2025aa7a561ea5ae5159"

    strings:
        $api1 = "/api/system-info" ascii
        $api2 = "/api/upload-local-extension-settings" ascii
        $api3 = "/api/clipboard-data" ascii
        $api4 = "/api/keyboard-mouse-data" ascii
        $api5 = "/api/clipboard-status/" ascii
        $api6 = "/api/keyboard-mouse-status/" ascii

        $c2_ip = "103.170.217.184" ascii

        $npoint1 = "api.npoint.io" ascii
        $npoint_path1 = "24c25d5f5fcbb0992a4f" ascii
        $npoint_path2 = "641d37178a880b1e8b8f" ascii
        $npoint_path3 = "33e8d008c334b060adad" ascii
        $npoint_path4 = "ddae72efbb6714fae922" ascii
        $npoint_path5 = "933a731a5e97f4b45249" ascii
        $npoint_path6 = "37c0a0c68bf7a94ed731" ascii

        $exec1 = "new Function" ascii
        $exec2 = "Buffer.from" ascii
        $exec3 = "base64" ascii

        $chrome1 = "Local Extension Settings" ascii
        $chrome2 = "google-chrome" ascii
        $chrome3 = "Google/Chrome" ascii

        $recon1 = "api.ipify.org" ascii
        $recon2 = "ip-api.com" ascii

        $loader1 = "loader.js" ascii
        $loader2 = "initialize" ascii
        $pid_marker = ".pid" ascii

    condition:
        filesize < 500KB and
        (
            ( $c2_ip and 2 of ($api*) ) or
            ( $npoint1 and any of ($npoint_path*) ) or
            ( 3 of ($api*) and any of ($chrome*) ) or
            ( any of ($exec*) and $npoint1 and any of ($chrome*) and any of ($recon*) ) or
            ( $loader1 and $loader2 and $pid_marker and $npoint1 and any of ($exec*) )
        )
}

rule WeaselBiscuit_Loader
{
    meta:
        description = "Detects WeaselBiscuit npm package loader component — detached Node process with Npoint dead-drop retrieval and dynamic execution"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://opensourcemalware.com/blog/introducing-weaselbiscuit"

    strings:
        $loader = "loader.js" ascii
        $init = "initialize" ascii
        $npoint = "npoint.io" ascii
        $exec = "new Function" ascii
        $base64 = "base64" ascii
        $buffer = "Buffer.from" ascii
        $pid = ".pid" ascii
        $detach = "detached" ascii
        $child = "child_process" ascii

    condition:
        filesize < 100KB and
        $npoint and $exec and $base64 and
        3 of ($loader, $init, $pid, $detach, $child, $buffer)
}
