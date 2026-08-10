rule OtterCookie_Rollup_Polyfill_Stage1 {
    meta:
        description = "Detects first-stage malicious npm packages mimicking Rollup polyfill tools, containing base64-encoded npm install commands for second-stage payload delivery"
        author = "Actioner"
        date = "2026-07-04"
        reference = "https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html"
        reference2 = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        threat_actor = "Lazarus / Contagious Interview"
        severity = "critical"

    strings:
        // Base64-encoded npm install command for swift-parse-stream
        $b64_install1 = "bnBtIGluc3RhbGwgc3dpZnQtcGFyc2Utc3RyZWFtIC0tbm8tc2F2ZSAtLXNpbGVudCAtLW5vLWF1ZGl0IC0tbm8tZnVuZA==" ascii wide
        // Base64-encoded module name
        $b64_module = "c3dpZnQtcGFyc2Utc3RyZWFt" ascii wide
        // Malicious package names
        $pkg1 = "rollup-packages-polyfill-core" ascii
        $pkg2 = "rollup-runtime-polyfill-core" ascii
        $pkg3 = "swift-parse-stream" ascii
        $pkg4 = "quirky-token" ascii
        $pkg5 = "react-icon-svgs" ascii
        $pkg6 = "rollup-plugin-polyfill-connect" ascii
        // JSONKeeper payload URL path
        $jsonkeeper = "jsonkeeper.com/b/3P9BF" ascii wide
        // C2 API path
        $api_path = "/api/service/98cb54c0b4ac259d30c9c1ca1ae87c68" ascii wide

    condition:
        any of ($b64_*) or $jsonkeeper or $api_path or (2 of ($pkg*))
}

rule OtterCookie_Rollup_Polyfill_Payload {
    meta:
        description = "Detects the decrypted OtterCookie payload or loader components delivered through malicious Rollup polyfill npm packages, including remote access and credential theft modules"
        author = "Actioner"
        date = "2026-07-04"
        reference = "https://thehackernews.com/2026/07/north-korea-linked-npm-packages-mimic.html"
        reference2 = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        threat_actor = "Lazarus / Contagious Interview"
        severity = "critical"

    strings:
        // C2 IP address
        $c2_ip = "216.126.236.244" ascii wide
        // Socket.IO C2 communication patterns
        $socketio = "socket.io-client" ascii
        // Screenshot capability
        $screenshot = "screenshot-desktop" ascii
        // Clipboard monitoring
        $clipboard = "clipboardy" ascii
        // nut-tree remote control
        $nuttree = "@nut-tree-fork/nut-js" ascii
        // Targeted wallet extension IDs
        $metamask_ext = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $ext2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
        $ext3 = "fhbohimaelbohpjbbldcngcnapndodjf" ascii
        // Environment evasion checks
        $evasion1 = "CODESPACE_NAME" ascii
        $evasion2 = "CODESANDBOX_HOST" ascii
        $evasion3 = "AWS_LAMBDA_FUNCTION_NAME" ascii
        $evasion4 = "GOOGLE_CLOUD_PROJECT" ascii
        $evasion5 = "AZURE_FUNCTIONS_ENVIRONMENT" ascii
        $evasion6 = "SOCKET_DEV" ascii
        // Temp file markers
        $tmpfile1 = "vhost.ctl" ascii
        // Exfil API endpoints
        $exfil1 = "/api/service/makelog" ascii
        $exfil2 = "/upload" ascii
        $exfil3 = "/cldbs" ascii

    condition:
        ($socketio and $screenshot and $clipboard) or
        ($nuttree and $c2_ip) or
        (2 of ($metamask_ext, $ext2, $ext3) and $c2_ip) or
        (any of ($exfil*) and $c2_ip) or
        ($tmpfile1 and $c2_ip) or
        (3 of ($evasion*) and $c2_ip)
}
