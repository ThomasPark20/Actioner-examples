/*
 * PHP2Shell Detection Rules - YARA
 * CVE-2026-109618 (OOM Corruption RCE) and CVE-2026-109619 (Use-After-Free RCE)
 * Generated: 2026-10-22 | Author: Actioner | Version: FINAL-1.0
 */

rule Exploit_PHP2Shell_Payload_CVE_2026_109618_109619
{
    meta:
        description = "Detects PHP2Shell exploitation payload in network captures or HTTP request logs targeting CVE-2026-109618 and CVE-2026-109619 via multipart POST with session upload progress abuse and PHPSESSID cookie"
        author = "Actioner"
        date = "2026-10-22"
        reference = "https://isc.sans.edu/diary/33440"
        severity = "critical"
        confidence = "medium"

    strings:
        $multipart = "multipart/form-data" ascii nocase
        $session_progress = "PHP_SESSION_UPLOAD_PROGRESS" ascii
        $phpsessid = "PHPSESSID=" ascii
        $content_disp = "Content-Disposition: form-data" ascii nocase
        $post_method = "POST " ascii

    condition:
        filesize < 10MB and
        $post_method and
        $multipart and
        $session_progress and
        $phpsessid and
        $content_disp
}
