rule Exploit_ShieldBreak_Defender_LPE
{
    meta:
        description = "Detects the ShieldBreak exploit tool that bypasses the CVE-2026-50656 patch in Microsoft Defender to achieve SYSTEM privilege escalation via Cloud Filter API abuse and CLFS log manipulation"
        author = "Actioner"
        date = "2026-08-16"
        reference = "https://github.com/MSNightmare/ShieldBreak"
        hash = "4e3146d667812ace49638e15f9dbb37b9e13f7222ed4984e065723715c692338"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pipe1 = "\\\\.\\pipe\\SHIELDBREAK" ascii wide
        $pipe2 = "SHIELDBREAK" ascii wide fullword

        $str1 = "ShieldBreak" ascii wide
        $str2 = "phoneinfo.dll" ascii wide nocase
        $str3 = "Warden.dll" ascii wide nocase
        $str4 = "BERLIN" ascii wide fullword
        $str5 = "WD_SHADOW" ascii wide
        $str6 = "WD_TARGET" ascii wide
        $str7 = "WD_SCAN" ascii wide
        $str8 = "QueueReporting" ascii wide

        $api1 = "MpClient.dll" ascii nocase
        $api2 = "cldapi.dll" ascii nocase
        $api3 = "NtSetInformationFile" ascii fullword
        $api4 = "NtDeleteFile" ascii fullword
        $api5 = "NtOpenDirectoryObject" ascii fullword

        $path1 = "BaseNamedObjects\\Restricted" ascii wide
        $path2 = "eicar_com.zip" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($pipe1 or ($pipe2 and $str1)) or
            (3 of ($str*) and 1 of ($api*)) or
            ($str2 and $str3 and $str1) or
            ($str5 and $str6 and $str7 and 1 of ($api*)) or
            (1 of ($path*) and 2 of ($str*) and 1 of ($api*))
        )
}

rule Payload_Warden_DLL_ShieldBreak
{
    meta:
        description = "Detects the Warden.dll payload used by the ShieldBreak exploit to duplicate the SYSTEM token and spawn a privileged shell"
        author = "Actioner"
        date = "2026-08-16"
        reference = "https://github.com/MSNightmare/ShieldBreak"
        hash = "691857f3f28049a7e33f5767d4e4eb3d739e1aa76c2a43c8cccadf871cfa7c1a"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $pipe = "SHIELDBREAK" ascii wide fullword
        $str1 = "conhost.exe" ascii wide nocase
        $str2 = "phoneinfo" ascii wide nocase
        $api1 = "DuplicateTokenEx" ascii fullword
        $api2 = "CreateProcessAsUser" ascii fullword
        $api3 = "ImpersonateNamedPipeClient" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $pipe and
        2 of ($api*) and
        1 of ($str*)
}
