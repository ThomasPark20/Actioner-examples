/*
  UTA0576 Post-Exploitation Credential Tools (Actioner)
  Detects Python tooling for LDAP recon, Kerberoasting, and credential
  harvesting deployed on compromised Ivanti Connect Secure appliances.
*/

rule apt_py_uta0576_credential_tools: CVE_2026_104935 UTA0576
{
  meta:
    author = "Actioner"
    date = "2026-10-16"
    description = "Detects UTA0576 post-exploitation Python scripts for LDAP reconnaissance, Kerberoasting, and credential harvesting on Ivanti Connect Secure."
    reference = "https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/"
    severity = "critical"

  strings:
    $icscap_dir = "/data/.icscap/" ascii
    $dsstatmond = "dsstatmond" ascii

    $ldap_tool1 = "ms-Mcs-AdmPwd" ascii wide
    $ldap_tool2 = "ms-FVE-RecoveryPassword" ascii wide
    $ldap_tool3 = "unixUserPassword" ascii wide

    $kerb1 = "Kerberoast" ascii nocase
    $spray1 = "spray_hits" ascii
    $spray2 = "sp_out.txt" ascii

  condition:
    (2 of ($ldap_tool*) and ($icscap_dir or $dsstatmond)) or
    ($icscap_dir and $dsstatmond) or
    ($kerb1 and ($spray1 or $spray2))
}
