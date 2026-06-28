import "pe"

rule Malware_Mistic_Backdoor_Loader
{
    meta:
        description = "Detects Mistic backdoor loader (version.dll) that hooks GetModuleFileNameW and LoadLibraryW to sideload EndpointDlp.dll via MpExtMs.exe"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        hash = "59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712"
        severity = "low"
        quality = "best-effort, untested against live samples; common API imports (GetModuleFileNameW, LoadLibraryW) may cause false positives on legitimate DLLs that reference the same APIs and filenames"

    strings:
        $hook1 = "GetModuleFileNameW" ascii fullword
        $hook2 = "LoadLibraryW" ascii fullword
        $target1 = "EndpointDlp.dll" ascii wide nocase
        $target2 = "MpExtMs" ascii wide nocase
        $target3 = "version.dll" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        pe.is_pe and
        all of ($hook*) and
        2 of ($target*)
}

rule Malware_Mistic_Backdoor_Payload
{
    meta:
        description = "Detects Mistic backdoor payload (EndpointDlp.dll) with in-memory execution and kill switch capabilities"
        author = "Actioner"
        date = "2026-06-28"
        reference = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        hash = "1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984"
        severity = "low"
        quality = "best-effort, untested against live samples; common API imports (VirtualAlloc, VirtualProtect, CreateThread) may cause false positives on legitimate PE files"

    strings:
        $name1 = "EndpointDlp" ascii wide
        $ua = "Microsoft-Delivery-Optimization" ascii wide
        $path = "/api/v1/telemetry" ascii wide
        $api1 = "VirtualAlloc" ascii fullword
        $api2 = "VirtualProtect" ascii fullword
        $api3 = "CreateThread" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        pe.is_pe and
        $name1 and
        ($ua or $path) and
        2 of ($api*)
}
