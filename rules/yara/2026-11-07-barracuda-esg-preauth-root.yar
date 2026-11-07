/*
    Barracuda ESG Pre-Auth Root Chain (CVE-2026-116606 / CVE-2026-111560)
    YARA rules for detecting crafted backup archives and post-exploitation artifacts
    Author: Actioner CTI Pipeline
    Date: 2026-11-07
    References:
        https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection
        https://labs.watchtowr.com/barracuda-networks-is-your-new-best-friend-barracuda-email-security-gateway-pre-auth-remote-root-rce-cve-2026-116606-cve-2026-111560/
*/

rule Barracuda_ESG_Crafted_Backup_CVE_2026_116606 {
    meta:
        description = "Detects crafted Barracuda ESG backup archives containing command injection payloads in system_timezone field (CVE-2026-116606 / CVE-2026-111560)"
        author = "Actioner CTI Pipeline"
        date = "2026-11-07"
        reference = "https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection"
        cve = "CVE-2026-116606, CVE-2026-111560"
        severity = "critical"

    strings:
        $backup_xml = "backup.xml" ascii
        $spam_config = "Spam_Config" ascii
        $tz_field = "system_timezone" ascii
        $inject1 = /system_timezone[^a-zA-Z0-9\r\n]{0,20}[;|`$]/ ascii
        $inject2 = /system_timezone[^a-zA-Z0-9\r\n]{0,20}\/bin\/(sh|bash)/ ascii
        $inject3 = /system_timezone[^a-zA-Z0-9\r\n]{0,20}\$\(/ ascii
        $tar_magic = { 75 73 74 61 72 }

    condition:
        $tar_magic at 257 and $backup_xml and $spam_config and $tz_field and any of ($inject*)
}

rule Barracuda_ESG_watchTowr_PoC_Script {
    meta:
        description = "Detects the watchTowr PoC / Detection Artifact Generator script for Barracuda ESG CVE-2026-116606 / CVE-2026-111560"
        author = "Actioner CTI Pipeline"
        date = "2026-11-07"
        reference = "https://github.com/watchtowrlabs/watchTowr-vs-Barracuda-RCE-CVE-2026-116606-CVE-2026-111560"
        severity = "high"

    strings:
        $tool_name = "watchTowr-vs-Barracuda" ascii
        $cve1 = "CVE-2026-116606" ascii
        $cve2 = "CVE-2026-111560" ascii
        $endpoint = "/cgi-mod/index.cgi" ascii
        $upload_field = "pu_bayesian_upload" ascii
        $pwd_field = "new_password" ascii

    condition:
        $tool_name and ($cve1 or $cve2) and $endpoint and ($upload_field or $pwd_field)
}

rule Barracuda_ESG_Post_Exploit_Timezone_Injection {
    meta:
        description = "Detects signs of timezone command injection on Barracuda ESG appliance filesystem (CVE-2026-111560)"
        author = "Actioner CTI Pipeline"
        date = "2026-11-07"
        reference = "https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection"
        cve = "CVE-2026-111560"
        severity = "critical"

    strings:
        $tz_path1 = "/home/product/code/config/tz" ascii
        $tz_path2 = "/etc/sysconfig/clock" ascii
        $fix_tz = "fix_tz.pl" ascii
        $inject_marker1 = /ZONE="[^"]*[;|`$][^"]*"/ ascii
        $inject_marker2 = /ZONE='[^']*[;|`$][^']*'/ ascii
    condition:
        any of ($tz_path*) and $fix_tz and any of ($inject_marker*)
}
