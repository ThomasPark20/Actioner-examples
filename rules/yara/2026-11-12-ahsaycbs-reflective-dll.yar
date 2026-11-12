rule Malware_AhsayCBS_Reflective_DLL_C2
{
    meta:
        description = "Detects the AhsayCBS reflectively loaded x64 DLL C2 implant via C2 URL and DoH resolver strings"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/ahsaycbs-webshells"
        hash = "bb2472cf5dc7e5c94216d355bf84fba2c8d088d03d61a1ac0d78639049cf5e1f"
        severity = "critical"

    strings:
        $c2_url = "creepexplosiondarknight.com/d" ascii wide
        $doh_quad9 = "dns.quad9.net" ascii wide
        $doh_google = "dns.google" ascii wide
        $machine_guid = "MachineGuid" ascii wide
        $bcrypt = "bcrypt" ascii

    condition:
        filesize < 2MB and
        $c2_url and
        1 of ($doh_quad9, $doh_google) and
        $machine_guid and
        $bcrypt
}
