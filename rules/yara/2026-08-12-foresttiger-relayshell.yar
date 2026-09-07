import "hash"

rule Lazarus_RelayShell_Webshell
{
    meta:
        description = "Detects RelayShell PHP webshell used by Lazarus Group as C2 relay infrastructure in Operation Dream Job"
        author = "Actioner"
        date = "2026-08-12"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
        severity = "critical"
        tlp = "WHITE"
        hash1 = "21c3ad4838c4324bc5f081021da5fb2e9073d0c9304087811c21eb47c9e22762"
        hash2 = "cc4e06aa378a190f71384c03023bb3d18a6d66e297d46701220e132963d2e222"

    strings:
        $key = "D9hWnVEqdgzJ67/B8euS0yKCIMrw5jc:fGUX3AakLH2oYQRp" ascii

        $id_1 = "PqCWom" ascii
        $id_2 = "a84038" ascii
        $id_3 = "biwbih" ascii
        $id_4 = "ddf7acea" ascii
        $id_5 = "enRU904U" ascii
        $id_6 = "fou2rm" ascii
        $id_7 = "kurhiW" ascii
        $id_8 = "qcrgl" ascii
        $id_9 = "rlzbiw" ascii
        $id_10 = "tmmvr1" ascii
        $id_11 = "win386" ascii

        $php_1 = "<?php" ascii nocase
        $php_2 = "session_start" ascii
        $php_3 = "file_put_contents" ascii
        $php_4 = "file_get_contents" ascii

    condition:
        filesize < 1MB and
        (
            hash.sha256(0, filesize) == "21c3ad4838c4324bc5f081021da5fb2e9073d0c9304087811c21eb47c9e22762" or
            hash.sha256(0, filesize) == "cc4e06aa378a190f71384c03023bb3d18a6d66e297d46701220e132963d2e222" or
            ($key) or
            (4 of ($id_*) and 2 of ($php_*))
        )
}
