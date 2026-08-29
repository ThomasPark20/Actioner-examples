rule PaperCut_CVE_2026_82078_Exploitation_Artifacts
{
    meta:
        description = "Detects artifacts associated with PaperCut NG/MF CVE-2026-82078 exploitation including JDBC exploitation error strings and reconnaissance commands"
        author = "Actioner"
        date = "2026-08-29"
        reference = "https://thehackernews.com/2026/08/attackers-chain-two-papercut-flaws-to.html"

    strings:
        $jdbc_error = "No suitable driver found for jdbc:no:x" ascii wide
        $db_error = "Database error looking up cardID: VALUES CAST" ascii wide
        $recon_cmd1 = "whoami & ver" ascii
        $recon_cmd2 = "whoami & ver & tasklist" ascii

    condition:
        1 of ($jdbc*, $db*) or all of ($recon*)
}
