rule JadePuffer_Ransomware_Payload_Strings
{
    meta:
        description = "Detects JadePuffer agentic ransomware payload strings including ransom table creation, encryption operations, and distinctive reconnaissance markers"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $ransom_table = "README_RANSOM" ascii wide nocase
        $enc_table = "config_info_enc" ascii wide
        $aes_encrypt = "AES_ENCRYPT" ascii wide
        $pwn_test = "_pwn_test.txt" ascii wide
        $pwn_cleanup = "_pwn_cleanup.txt" ascii wide
        $xadmin = "xadmin" ascii wide
        $ransom_msg = "YOUR DATA HAS BEEN ENCRYPTED" ascii wide nocase
        $btc_addr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" ascii wide
        $proton_email = "e78393397@proton.me" ascii wide
        $high_roi = "High-ROI databases" ascii wide nocase
        $backed_up = "data already backed up" ascii wide nocase

    condition:
        3 of them
}
