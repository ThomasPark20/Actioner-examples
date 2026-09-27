/*
    YARA Rules for Oracle PeopleSoft CVE-2026-35273 Campaign
    ShinyHunters/UNC6240 - Web Shells and SIDEEYE Backdoor
    Author: Actioner CTI
    Date: 2026-09-27
    References:
        - https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-renewed-mass-exploitation-campaign-targeting-oracle-peoplesoft
        - https://www.bleepingcomputer.com/news/security/shinyhunters-uses-waf-bypass-trick-in-oracle-peoplesoft-attacks/
*/

rule UNC6240_WebShell_x_jsp {
    meta:
        description = "Detects x.jsp web shell used by UNC6240/ShinyHunters in CVE-2026-35273 exploitation"
        author = "Actioner CTI"
        date = "2026-09-27"
        hash = "48b4a0827da7bbfce9fb52464f8a659dea7a035189c52c506c0bfb4b1c3fe494"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-renewed-mass-exploitation-campaign-targeting-oracle-peoplesoft"
        severity = "critical"
        confidence = "high"

    strings:
        // ASCII char array used to reconstruct /bin/sh to evade static signatures
        $evasion_array = "47,98,105,110,47,115,104" ascii
        // Hex decode parameter pattern
        $param_c = "request.getParameter(\"c\")" ascii
        // Response prefix used by this shell
        $response_r = "\"R:\"" ascii
        // ProcessBuilder execution pattern
        $exec_pattern = "ProcessBuilder" ascii
        // cmd.exe invocation
        $cmd_win = "cmd.exe" ascii nocase
        // Dual-OS detection pattern
        $os_check = "os.name" ascii

    condition:
        $evasion_array or
        (filesize < 10KB and $param_c and $response_r and $exec_pattern and ($cmd_win or $os_check))
}

rule UNC6240_WebShell_u_jsp {
    meta:
        description = "Detects u.jsp chunked file upload web shell used by UNC6240/ShinyHunters"
        author = "Actioner CTI"
        date = "2026-09-27"
        hash = "2bee941fb40519d0d1ec52bd79a8f63fc65aac6455c8f2d6b668e3360dfdb5d7"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-renewed-mass-exploitation-campaign-targeting-oracle-peoplesoft"
        severity = "critical"
        confidence = "high"

    strings:
        // File write response prefix
        $resp_w = "\"W:\"" ascii
        // Error response prefix
        $resp_e = "\"E:\"" ascii
        // Execution result prefix
        $resp_r = "\"R:\"" ascii
        // Execution error prefix
        $resp_x = "\"X:\"" ascii
        // Append mode parameter
        $param_m = "request.getParameter(\"m\")" ascii
        // File path parameter
        $param_n = "request.getParameter(\"n\")" ascii
        // Base64 chunk parameter
        $param_a = "request.getParameter(\"a\")" ascii
        // Execute command parameter
        $param_x = "request.getParameter(\"x\")" ascii
        // Base64 decode
        $b64_decode = "Base64" ascii

    condition:
        filesize < 10KB and
        (3 of ($resp_*)) and
        (3 of ($param_*)) and
        $b64_decode
}

rule UNC6240_SIDEEYE_Dropper_Ple64 {
    meta:
        description = "Detects Ple64.exe trojanized Light Alloy installer that drops SIDEEYE backdoor"
        author = "Actioner CTI"
        date = "2026-09-27"
        hash = "3ba215692665513abfffd4e815c5c45f2d41e5dcc4283a2a3b740930c5c417c3"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-renewed-mass-exploitation-campaign-targeting-oracle-peoplesoft"
        severity = "critical"
        confidence = "high"

    strings:
        // Light Alloy media player strings
        $la1 = "Light Alloy" ascii wide
        $la2 = "Ple64" ascii wide
        // Certificate subject
        $cert = "Tobias Weihmann Software Development" ascii wide
        // VMProtect signatures
        $vmp1 = ".vmp0" ascii
        $vmp2 = ".vmp1" ascii
        $vmp3 = "VMProtect" ascii
        // C2 IP address
        $c2_ip = "162.219.30.165" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize > 4MB and filesize < 8MB and
        (
            ($c2_ip) or
            (any of ($la*) and any of ($vmp*)) or
            ($cert and any of ($vmp*))
        )
}

rule UNC6240_NeoReGeorg_Tunnel_JSP {
    meta:
        description = "Detects Neo-reGeorg tunneling web shells (tunnel.jsp/tunnel.jspx) used by UNC6240"
        author = "Actioner CTI"
        date = "2026-09-27"
        hash1 = "419c571ee38b7e7266d130c4b6bbc4dd0ef44d6e5f3bc02cc2cf73b762f07c86"
        hash2 = "ba14419beb2ec0bb94cab6298c14d7fb3e1d819366fe378290c0c2a4d97f7e07"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-renewed-mass-exploitation-campaign-targeting-oracle-peoplesoft"
        severity = "high"
        confidence = "medium"

    strings:
        // Neo-reGeorg specific patterns
        $neo1 = "neoreg" ascii nocase
        $neo2 = "Georg" ascii
        // SOCKS proxy patterns in JSP context
        $socks1 = "CONNECT" ascii
        $socks2 = "socket" ascii nocase
        // JSP imports for tunnel functionality
        $import1 = "java.net.Socket" ascii
        $import2 = "java.io.InputStream" ascii
        $import3 = "javax.crypto" ascii
        // Encryption/encoding
        $crypto1 = "AES" ascii
        $crypto2 = "Cipher" ascii

    condition:
        filesize < 50KB and
        (
            (any of ($neo*) and any of ($import*)) or
            (all of ($import*) and all of ($crypto*) and any of ($socks*))
        )
}
