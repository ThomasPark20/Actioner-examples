rule APT41_BlackX_Installer : bootkit apt41
{
    meta:
        description = "Detects BlackX UEFI bootkit installer or payload artifacts via distinctive strings"
        author = "Actioner"
        date = "2026-10-28"
        reference = "https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide
        $payload_name = "PVMDIJGKAX2" ascii wide
        $c2_domain = "archivetj.com" ascii wide
        $export_fn = "create_plugin" ascii
        $xdd_marker = "xdd" ascii fullword
        $staging_path = "\\ProgramData\\Intel\\inst.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule APT41_BlackX_OxiDLLRunner : sideload apt41
{
    meta:
        description = "Detects BlackX OxiDLLRunner DLL sideloaded via jcef_helper.exe renamed as googleupdate.exe"
        author = "Actioner"
        date = "2026-10-28"
        reference = "https://blog.netmanageit.com/blackx-uefi-bootkit-central-asia-diplomatic-targets/"
        hash = "af8a983b9ada07eae1259bf2953abd40"
        tlp = "WHITE"
        severity = "high"

    strings:
        $orig_name = "jcef_helper.exe" ascii wide
        $c2 = "archivetj.com" ascii wide
        $export = "create_plugin" ascii
        $v8_snap = "v8_context_snapshot.bin" ascii wide
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide

    condition:
        uint16(0) == 0x5A4D and (($orig_name and ($c2 or $export)) or (3 of them))
}

rule APT41_BlackX_Certificate : certificate apt41
{
    meta:
        description = "Detects binaries signed with the revoked certificate used by BlackX bootkit kernel driver"
        author = "Actioner"
        date = "2026-10-28"
        reference = "https://thehackernews.com/2026/10/blackx-uefi-bootkit-bypasses-secure.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $cert_serial = { 0B CD F5 E0 DA 32 D6 89 00 B8 B7 63 84 59 D0 72 }
        $cert_cn = "Wenjiang District Mingyu Network Technology Service Studio" ascii wide

    condition:
        uint16(0) == 0x5A4D and any of them
}
