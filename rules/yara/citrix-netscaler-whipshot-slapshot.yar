rule Malware_WHIPSHOT_PHP_WebShell
{
    meta:
        description = "Detects WHIPSHOT PHP web shell deployed on compromised Citrix NetScaler appliances via CVE-2026-88771/CVE-2026-88772"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://thehackernews.com/2026/09/attackers-exploit-netscaler-flaw-for.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $php_open = "<?php" ascii nocase
        $err_suppress = "error_reporting(0)" ascii
        $header_read = "$_SERVER['HTTP_" ascii
        $xcmd_header = "X-Cmd-" ascii
        $base64_decode = "base64_decode" ascii
        $http_proxy = "fsockopen" ascii
        $status_check = "SLAPSHOT" ascii nocase
        $response_404 = "http_response_code(404)" ascii
        $loopback = "127.0.0.1" ascii

    condition:
        filesize < 100KB and
        $php_open and
        (
            ($err_suppress and $base64_decode and $header_read and $xcmd_header) or
            ($http_proxy and $loopback and $base64_decode) or
            ($response_404 and $base64_decode and $xcmd_header) or
            ($status_check and $base64_decode)
        )
}

rule Malware_SLAPSHOT_Python_Tunneler
{
    meta:
        description = "Detects SLAPSHOT Python TCP tunneling tool used for lateral movement from compromised Citrix NetScaler appliances"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://securityaffairs.com/200046/security/whipshot-and-slapshot-the-tools-behind-an-active-citrix-netscaler-campaign.html"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $import_socket = "import socket" ascii
        $import_select = "import select" ascii
        $import_threading = "import threading" ascii
        $uxdport = ".uxdport" ascii
        $uxdlock = ".uxdlock" ascii
        $loopback_bind = "127.0.0.1" ascii
        $sock_create = "socket.socket" ascii
        $sock_connect = ".connect(" ascii
        $timeout_cleanup = "self_terminate" ascii nocase

    condition:
        filesize < 500KB and
        (
            ($uxdport and $uxdlock) or
            ($import_socket and $import_select and $loopback_bind and $sock_connect and 1 of ($uxdport, $uxdlock, $timeout_cleanup)) or
            ($import_socket and $import_threading and $sock_create and $sock_connect and 1 of ($uxdport, $uxdlock))
        )
}
