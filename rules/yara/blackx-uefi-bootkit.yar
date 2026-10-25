rule APT41_BlackX_Installer_Artifacts
{
    meta:
        description = "Detects BlackX UEFI bootkit installer artifacts via distinctive strings including the encrypted payload filename and RC4 key"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $installer_payload = "PVMDIJGKAX2" ascii wide
        $rc4_key = "Q46F6MDLI3RX2KV1" ascii wide
        $install_path = "\\ProgramData\\Intel\\inst.exe" ascii wide
        $task_name = "Secure-Boot-Update" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        2 of them
}

rule APT41_BlackX_OxiDLLRunner_Strings
{
    meta:
        description = "Detects BlackX OxiDLLRunner or Rust payload components via C2 domain, exported function, and attribution strings"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $c2_domain = "archivetj.com" ascii wide
        $export_fn = "create_plugin" ascii wide
        $xdd_marker = "xdd" ascii fullword
        $v8_payload = "v8_context_snapshot.bin" ascii wide
        $sideload_name = "googleupdate.exe" ascii wide nocase

    condition:
        filesize < 50MB and
        (
            ($c2_domain and 1 of ($export_fn, $xdd_marker)) or
            (3 of them)
        )
}

rule APT41_BlackX_KernelDriver_Certificate
{
    meta:
        description = "Detects files signed with the revoked certificate used by the BlackX bootkit kernel driver (Wenjiang District Mingyu Network Technology Service Studio)"
        author = "Actioner"
        date = "2026-10-25"
        reference = "https://securelist.com/uefi-bootkit-blackx/121539/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $cert_cn = "Wenjiang District Mingyu Network Technology Service Studio" ascii wide
        $cert_cn_zh = {E6 B8 A9 E6 B1 9F E5 8C BA E6 98 8E E5 AE 87 E7 BD 91 E7 BB 9C E6 8A 80 E6 9C AF E6 9C 8D E5 8A A1 E5 B7 A5 E4 BD 9C E5 AE A4}
        $cert_serial = "0bcdf5e0da32d68900b8b7638459d072" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        any of them
}
