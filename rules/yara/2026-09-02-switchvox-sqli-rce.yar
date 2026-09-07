rule Exploit_CVE_2026_9586_Switchvox_SQLi_Payload
{
    meta:
        description = "Detects CVE-2026-9586 exploit payload targeting Sangoma Switchvox /pa endpoint via PolycomIPPhone XML with SQL injection containing COPY TO PROGRAM"
        author = "Actioner"
        date = "2026-09-02"
        reference = "https://horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $xml_tag = "<PolycomIPPhone>" ascii nocase
        $phone_ip = "<PhoneIP>" ascii nocase
        $sqli_copy = "COPY" ascii nocase fullword
        $sqli_to_program = "TO PROGRAM" ascii nocase

    condition:
        $xml_tag and $phone_ip and $sqli_copy and $sqli_to_program
}

rule Exploit_CVE_2026_9586_Switchvox_Reverse_Shell
{
    meta:
        description = "Detects reverse shell payload patterns associated with CVE-2026-9586 Switchvox exploitation including netcat and bash reverse shells in SQL context"
        author = "Actioner"
        date = "2026-09-02"
        reference = "https://horizon3.ai/attack-research/disclosures/cve-2026-9586-sangoma-switchvox-rce/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $xml_tag = "<PolycomIPPhone>" ascii nocase
        $phone_ip = "<PhoneIP>" ascii nocase
        $revshell1 = "nc " ascii
        $revshell2 = "/bin/bash" ascii
        $revshell3 = "/bin/sh" ascii
        $revshell4 = "| sh" ascii
        $sqli_marker = "COPY" ascii nocase fullword

    condition:
        $xml_tag and $phone_ip and $sqli_marker and 1 of ($revshell*)
}
