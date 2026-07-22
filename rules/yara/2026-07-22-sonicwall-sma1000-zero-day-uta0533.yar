rule UTA0533_ROOTRUN_Setuid_Binary
{
    meta:
        description = "Detects ROOTRUN (xzfind) setuid privilege escalation binary deployed by UTA0533"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "81a9af3846bad3a1107164ff7cf0a08e020b31a3b32fd17866e17d4c1565f7f2"
        tlp = "white"

    strings:
        $elf_header = { 7F 45 4C 46 }
        $setuid_call = "setuid" ascii
        $bash = "/bin/bash" ascii
        $xzfind = "xzfind" ascii

    condition:
        $elf_header at 0 and
        filesize < 20KB and
        filesize > 10KB and
        2 of ($setuid_call, $bash, $xzfind)
}

rule UTA0533_KNUCKLEBALL_JAR_Injector
{
    meta:
        description = "Detects KNUCKLEBALL (deploy_new.py) Python-based JAR injector used by UTA0533"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
        tlp = "white"

    strings:
        $attach_pid = ".attach_pid" ascii
        $java_pid = ".java_pid" ascii
        $agent_wp8 = "agent_wp8" ascii
        $agent_wp9 = "agent_wp9" ascii
        $unit_conf = "unit/conf.json" ascii
        $load_instrument = "load instrument false" ascii
        $workplace_startup = "CommandStartup" ascii
        $deploy_new = "deploy_new" ascii

    condition:
        filesize < 200KB and
        3 of them
}

rule UTA0533_Suo5_Proxy_JAR
{
    meta:
        description = "Detects Suo5 (agent_wp8.jar) HTTP forwarding proxy used by UTA0533"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee"
        tlp = "white"

    strings:
        $pk_header = { 50 4B 03 04 }
        $class_target = "com/aventail/jsp/workplace/error_jsp" ascii
        $agent_wp8 = "agent_wp8" ascii
        $mozilla6 = "Mozilla/6.0" ascii

    condition:
        $pk_header at 0 and
        filesize < 100KB and
        2 of ($class_target, $agent_wp8, $mozilla6)
}

rule UTA0533_ORANGETAIL_Webshell
{
    meta:
        description = "Detects ORANGETAIL (agent_wp9.jar) custom Java web shell used by UTA0533"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        hash = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
        tlp = "white"

    strings:
        $pk_header = { 50 4B 03 04 }
        $class_target = "com/aventail/jsp/workplace/dialogs/errorDialog_jsp" ascii
        $agent_wp9 = "agent_wp9" ascii
        $mozilla6 = "Mozilla/6.0" ascii
        $string_valueof = "String.valueOf" ascii
        $aes = "AES" ascii

    condition:
        $pk_header at 0 and
        filesize < 100KB and
        ($class_target or $agent_wp9) and
        2 of ($mozilla6, $string_valueof, $aes)
}

rule UTA0533_Malformed_UserAgent_Gate
{
    meta:
        description = "Detects the malformed User-Agent string hardcoded in ORANGETAIL and Suo5 as an authentication gate"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        tlp = "white"

    strings:
        $ua_full = "Mozilla/6.0 (Windows NT 11.0; Win64; x64) AppleWebKit/1537.136 (KHTML, like Gecko) Chrome/149.0.0.1 Safari/1537.136" ascii wide
        $ua_mozilla6 = "Mozilla/6.0 (Windows NT 11.0" ascii wide
        $ua_chrome149 = "Chrome/149.0.0.1" ascii wide

    condition:
        $ua_full or ($ua_mozilla6 and $ua_chrome149)
}

rule UTA0533_CVE_2026_15410_Exploit_Staging
{
    meta:
        description = "Detects staging artifacts for CVE-2026-15410 exploitation of SonicWall remove_hotfix path traversal"
        author = "Actioner"
        date = "2026-07-22"
        reference = "https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/"
        tlp = "white"

    strings:
        $traversal = "../../../../../tmp/" ascii
        $remove_hotfix = "remove_hotfix" ascii
        $exec_remove = "execRemoveHotfix" ascii
        $ctrl_service = "sysCtrl" ascii
        $product_uuid = "product_uuid" ascii
        $b64_marker = "hypdate" ascii

    condition:
        filesize < 500KB and
        3 of them
}
