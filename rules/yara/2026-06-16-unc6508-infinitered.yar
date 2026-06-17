/*
 * UNC6508 INFINITERED Campaign - YARA Detection Rules
 * Source: https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
 * Generated: 2026-06-16
 */

rule G_Backdoor_INFINITERED_1 {
    meta:
        author = "Google Threat Intelligence Group (GTIG)"
        description = "Detects INFINITERED custom backdoor deployed by UNC6508 against REDCap servers"
        date = "2026-06-15"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research"
        threat_actor = "UNC6508"
        tlp = "WHITE"
    strings:
        $magic_flag = "ej671a16i7fd8202nu6ltfg5p6x7u"
        $magic_flag_base64 = "ej671a16i7fd8202nu6ltfg5p6x7u" base64
        $marker = "b49e334d-9c01-463e-9bc5-00a6920fb66e"
        $marker_base64 = "YjQ5ZTMzNGQtOWMwMS00NjNlLTliYzUtMDBhNjkyMGZiNjZl"
        $s1 = "substr($cookieValue, strlen($magic_flag));"
        $s2 = "getcwd(), php_uname(), phpversion(), $_SERVER['SERVER_SOFTWARE']"
        $s3 = "'data' => encrypt($data, $key)"
        $s4 = "$data = shell_exec($command);"
        $s5 = "move_uploaded_file($tmpPath, $fileName)"
        $s6 = "$data = implode('|', $fields)"
        $b_s1 = "substr($cookieValue, strlen($magic_flag));" base64
        $b_s2 = "getcwd(), php_uname(), phpversion(), $_SERVER['SERVER_SOFTWARE']" base64
        $b_s3 = "'data' => encrypt($data, $key)" base64
        $b_s4 = "$data = shell_exec($command);" base64
        $b_s5 = "move_uploaded_file($tmpPath, $fileName)" base64
        $b_s6 = "$data = implode('|', $fields)" base64
        $t1 = "(isset($_POST['username']) && $_POST['password'])"
        $t2 = "INSERT INTO redcap_sessions (session_id, session_data, session_expiration) VALUES ('$session_id', '$str', FROM_UNIXTIME($expiration_timestamp))"
        $t3 = "encrypt($currentUTC . '[::]' . $_POST['username'] . '[::]' . $_POST['password']);"
        $t4 = "redcap_connect.php"
        $b_t1 = "(isset($_POST['username']) && $_POST['password'])" base64
        $b_t2 = "INSERT INTO redcap_sessions (session_id, session_data, session_expiration) VALUES ('$session_id', '$str', FROM_UNIXTIME($expiration_timestamp))" base64
        $b_t3 = "encrypt($currentUTC . '[::]' . $_POST['username'] . '[::]' . $_POST['password']);" base64
        $b_t4 = "redcap_connect.php" base64
        $u1 = "$zip->open($filename) === TRUE)"
        $u2 = "$hooks_encode ="
        $u3 = "$auth_encode ="
        $u4 = "$file_content_hooks = $zip->getFromName($file_hooks);"
        $u5 = "$file_content_auth = $zip->getFromName($file_auth);"
        $u6 = "$file_content_upgrade = $zip->getFromName($file_upgrade);"
        $u7 = "str_replace($search_content, $hooks_decode, $file_content_hooks);"
        $u8 = "str_replace($search_content, $upgrade_decode, $file_content_upgrade);"
        $u9 = "str_replace($search_content, $auth_decode, $file_content_auth);"
        $b_u1 = "$zip->open($filename) === TRUE)" base64
        $b_u2 = "$hooks_encode =" base64
        $b_u3 = "$auth_encode =" base64
        $b_u4 = "$file_content_hooks = $zip->getFromName($file_hooks);" base64
        $b_u5 = "$file_content_auth = $zip->getFromName($file_auth);" base64
        $b_u6 = "$file_content_upgrade = $zip->getFromName($file_upgrade);" base64
        $b_u7 = "str_replace($search_content, $hooks_decode, $file_content_hooks);" base64
        $b_u8 = "str_replace($search_content, $upgrade_decode, $file_content_upgrade);" base64
        $b_u9 = "str_replace($search_content, $auth_decode, $file_content_auth);" base64
        $filemarker = "<?php"
    condition:
        filesize < 1MB and $filemarker in (0 .. 128) and (((any of ($magic*) or any of ($marker*)) and (any of ($s*) or any of ($t*) or any of ($u*))) or 4 of ($s*) or 4 of ($b_s*) or all of ($t*) or all of ($b_t*) or 6 of ($u*) or 6 of ($b_u*))
}

rule UNC6508_INFINITERED_CredHarvester {
    meta:
        author = "Actioner"
        description = "Detects INFINITERED credential harvester component targeting REDCap sessions table"
        date = "2026-06-16"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research"
        threat_actor = "UNC6508"
        tlp = "WHITE"
    strings:
        $session_prefix = "xc32038474a"
        $session_prefix_base64 = "xc32038474a" base64
        $delim = "[::]"
        $redcap_sessions = "redcap_sessions"
        $encrypt_cred = "encrypt($currentUTC"
        $post_user = "$_POST['username']"
        $post_pass = "$_POST['password']"
        $php = "<?php"
    condition:
        filesize < 500KB and $php in (0 .. 128) and ($session_prefix or $session_prefix_base64) and 2 of ($delim, $redcap_sessions, $encrypt_cred, $post_user, $post_pass)
}

rule UNC6508_INFINITERED_WebShell_HelpPHP {
    meta:
        author = "Actioner"
        description = "Detects INFINITERED help.php web shell used for initial persistence on REDCap"
        date = "2026-06-16"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research"
        threat_actor = "UNC6508"
        tlp = "WHITE"
    strings:
        $guid = "b49e334d-9c01-463e-9bc5-00a6920fb66e"
        $guid_b64 = "YjQ5ZTMzNGQtOWMwMS00NjNlLTliYzUtMDBhNjkyMGZiNjZl"
        $cookie_c2 = "REDCAP-TOKEN"
        $magic = "ej671a16i7fd8202nu6ltfg5p6x7u"
        $shell_exec = "shell_exec($command)"
        $php = "<?php"
    condition:
        filesize < 1MB and $php in (0 .. 128) and (any of ($guid, $guid_b64, $magic)) and ($cookie_c2 or $shell_exec)
}
