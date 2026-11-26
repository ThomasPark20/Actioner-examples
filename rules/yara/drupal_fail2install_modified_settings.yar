rule Exploit_Drupal_Fail2Install_Modified_Settings
{
    meta:
        description = "Detects Drupal settings.php files modified to point to an attacker-controlled SQLite database, a hallmark of CVE-2026-132165 Fail2Install post-exploitation."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://www.drupal.org/sa-core-2026-017"
        reference2 = "https://www.stepsecurity.io/blog/fail2install-cve-2026-132165"
        severity = "high"
        tlp = "WHITE"

    strings:
        $settings_marker = "$databases" ascii
        $driver_sqlite = "'driver' => 'sqlite'" ascii
        $driver_sqlite2 = "\"driver\" => \"sqlite\"" ascii
        $sqlite_path_php = /database.{0,64}=>.{0,128}\.php/ ascii
        $drupal_hash_salt = "$settings['hash_salt']" ascii

    condition:
        filesize < 1MB and
        $settings_marker and
        $drupal_hash_salt and
        ($driver_sqlite or $driver_sqlite2) and
        $sqlite_path_php
}
