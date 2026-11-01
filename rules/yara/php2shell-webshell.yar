rule PHP2Shell_Webshell_Indicator
{
    meta:
        description = "Detects PHP webshell artifacts associated with PHP2Shell exploitation, including known attacker tool markers and payload strings written to web roots"
        author = "CTI Analyst"
        date = "2026-11-01"
        reference = "https://www.zscaler.com/blogs/security-research/cve-2026-109618-and-cve-2026-109619-php-vulnerable-unauthenticated-rce"
        reference_2 = "https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/"
        severity = "high"
        cve = "CVE-2026-109618,CVE-2026-109619"

    strings:
        $exploit_marker1 = "shellflow-php2shell" ascii
        $exploit_marker2 = "shellflow_poc" ascii
        $exploit_marker3 = "neo_obj_inject" ascii
        $exploit_marker4 = "NeoMM2026" ascii
        $exploit_marker5 = "sf618_ec172709c8b74601" ascii
        $exploit_marker6 = "neosc4n00000000000000002" ascii

        $payload1 = "system('echo" ascii
        $payload2 = "exploited digga" ascii
        $payload3 = "pwned.txt" ascii

        $obj_inject = /x\|O:\d+:"[^"]+":/ ascii

    condition:
        filesize < 500KB and
        (
            any of ($exploit_marker*) or
            (any of ($payload*)) or
            ($obj_inject)
        )
}

rule PHP2Shell_Heap_Spray_Payload
{
    meta:
        description = "Detects heap spray payloads used in PHP2Shell exploitation, characterized by large blocks of repeated characters sent as multipart file upload data"
        author = "CTI Analyst"
        date = "2026-11-01"
        reference = "https://www.zscaler.com/blogs/security-research/cve-2026-109618-and-cve-2026-109619-php-vulnerable-unauthenticated-rce"
        severity = "medium"
        cve = "CVE-2026-109618"

    strings:
        $multipart = "Content-Type: multipart/form-data" ascii nocase
        $filename_poc = "filename=\"poc.bin\"" ascii
        $content_octet = "Content-Type: application/octet-stream" ascii
        $heap_spray = { 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 }

    condition:
        filesize < 50KB and
        $filename_poc and
        ($content_octet or $multipart) and
        $heap_spray
}

rule Generic_PHP_Webshell_Suspicious
{
    meta:
        description = "Detects generic PHP webshell patterns -- PHP tag with multiple dangerous functions and base64_decode. Not PHP2Shell-specific; separated to avoid false positives on legitimate PHP files."
        author = "CTI Analyst"
        date = "2026-11-01"
        reference = "https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/"
        severity = "medium"

    strings:
        $php_tag = "<?php" ascii nocase
        $webshell_func1 = "system(" ascii
        $webshell_func2 = "exec(" ascii
        $webshell_func3 = "passthru(" ascii
        $webshell_func4 = "shell_exec(" ascii
        $webshell_func5 = "popen(" ascii
        $webshell_func6 = "proc_open(" ascii
        $base64 = "base64_decode(" ascii

    condition:
        filesize < 500KB and
        $php_tag and 2 of ($webshell_func*) and $base64
}
