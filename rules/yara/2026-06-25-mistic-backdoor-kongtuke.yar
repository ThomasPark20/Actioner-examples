import "pe"

rule Mistic_MLTBackdoor_Payload
{
    meta:
        description = "Detects MLTBackdoor/Mistic backdoor payload based on custom protocol magic bytes, DGA constants, and BOF loader artifacts"
        author = "Actioner CTI"
        date = "2026-06-25"
        reference = "https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor"
        reference2 = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        hash1 = "1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984"
        hash2 = "9e52cc90cff150abe21f0a6440e86e0a99ff383b81061b96def8948e21d0ac66"
        hash3 = "ced6b0f44410f6133ad63b61e04613a8b56cc3338d7b34497540e9541163e7ec"
        confidence = "high"
        compile_status = "pending"

    strings:
        // MLT protocol magic bytes (0x014D4C54 = \x01MLT)
        $magic = { 01 4D 4C 54 }

        // DGA LCG constants
        $lcg_mult = { 0D 66 19 00 }   // 0x0019660D little-endian
        $lcg_inc  = { 5F F3 6E 3C }   // 0x3C6EF35F little-endian

        // User-Agent string used for C2
        $ua = "Microsoft-Delivery-Optimization/10.1" ascii wide

        // C2 URI path
        $uri = "/api/v1/telemetry" ascii wide

        // BOF loader DJB2 hashes for Beacon API functions
        $bof_beacon_parse   = { A2 4B 49 E2 }  // BeaconDataParse 0xE2494BA2
        $bof_beacon_printf  = { 60 86 0D 70 }  // BeaconPrintf 0x700D8660
        $bof_beacon_output  = { 1E B8 F4 6D }  // BeaconOutput 0x6DF4B81E

        // BOF NT API wrapper hashes
        $bof_nt_alloc    = { 14 9B AF A7 }  // BeaconNtAllocateVirtualMemory 0xA7AF9B14
        $bof_nt_protect  = { 90 61 C5 B4 }  // BeaconNtProtectVirtualMemory 0xB4C56190
        $bof_nt_create   = { A3 51 C7 FD }  // BeaconNtCreateFile 0xFDC751A3

        // Indirect syscall Nt API hashes (Hell's Gate style)
        $nthash_alloc   = { 4C C3 93 67 }  // NtAllocateVirtualMemory 0x6793C34C
        $nthash_protect = { C8 62 29 08 }  // NtProtectVirtualMemory 0x082962C8
        $nthash_thread  = { 30 21 0C CB }  // NtCreateThreadEx 0xCB0C2130

        // Anti-analysis VM detection strings
        $vm_vmware = "VMwareVMware" ascii
        $vm_vbox   = "VBoxVBoxVBox" ascii
        $vm_xen    = "XenVMMXenVMM" ascii
        $vm_kvm    = "KVMKVMKVM" ascii

        // Known C2 domains
        $c2_1 = "carrolc.com" ascii
        $c2_2 = "cwrtwright.com" ascii
        $c2_3 = "thomphon.com" ascii
        $c2_4 = "powwowski.com" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            ($magic and $ua) or
            ($magic and $uri) or
            ($magic and 2 of ($lcg_*)) or
            ($magic and 2 of ($bof_*)) or
            (3 of ($nthash_*) and 2 of ($bof_*)) or
            ($ua and $uri and 1 of ($c2_*)) or
            (2 of ($lcg_*) and 2 of ($bof_*)) or
            (3 of ($vm_*) and $magic)
        )
}

rule Mistic_MLTBackdoor_Loader_VersionDLL
{
    meta:
        description = "Detects the Mistic/MLTBackdoor version.dll loader that hooks GetModuleFileNameW and LoadLibraryW for the DLL sideloading chain"
        author = "Actioner CTI"
        date = "2026-06-25"
        reference = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        hash = "59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712"
        confidence = "high"
        compile_status = "pending"

    strings:
        $hook1 = "GetModuleFileNameW" ascii wide
        $hook2 = "LoadLibraryW" ascii wide
        $target_dll = "EndpointDlp.dll" ascii wide
        $target_exe = "MpExtMs.exe" ascii wide
        $target_exe2 = "mpextms.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        pe.exports("GetFileVersionInfoA") and
        (
            ($target_dll and ($target_exe or $target_exe2)) or
            (all of ($hook*) and $target_dll)
        )
}

rule Mistic_MLTBackdoor_RC4_Encrypted_Payload
{
    meta:
        description = "Detects RC4-encrypted MLTBackdoor payload data.bin files based on the header structure containing payload size followed by 32-byte RC4 key"
        author = "Actioner CTI"
        date = "2026-06-25"
        reference = "https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor"
        confidence = "medium"
        compile_status = "pending"

    strings:
        // EndpointDlp.dll and version.dll names that may appear in archive
        $name1 = "endpointdlp.dll" ascii nocase
        $name2 = "version.dll" ascii nocase
        $name3 = "MpExtMs.exe" ascii nocase
        $name4 = "mpextms.exe" ascii nocase
        $name5 = "data.bin" ascii nocase

    condition:
        (
            // ZIP or MSI archive containing sideload components
            (uint32(0) == 0x04034B50 and 3 of ($name*)) or
            // MSI magic
            (uint32(0) == 0xE011CFD0 and 3 of ($name*))
        )
}

rule Mistic_MLTBackdoor_Hashes
{
    meta:
        description = "Detects known Mistic/MLTBackdoor samples by SHA256 hash match on import table or code section characteristics"
        author = "Actioner CTI"
        date = "2026-06-25"
        reference = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        reference2 = "https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor"
        confidence = "high"
        compile_status = "pending"

    strings:
        // Anti-analysis process name SHA256 hashes embedded in binary
        // x64dbg.exe
        $proc_hash_1 = { 9e 87 77 66 1a 1a d9 c9 83 f0 30 60 f0 a0 4a 32 }
        // procmon64.exe
        $proc_hash_2 = { 75 63 50 09 a0 0c b2 6d 2f 53 2a d9 74 ed e5 97 }
        // wireshark.exe
        $proc_hash_3 = { ac 66 c2 d4 7c de fb 22 18 22 b9 07 4c 98 10 43 }
        // vmtoolsd.exe
        $proc_hash_4 = { fc 86 49 54 7a d0 ec e9 3a d8 2d e7 5c b6 b8 75 }
        // vboxservice.exe
        $proc_hash_5 = { 68 70 e3 bb f2 44 7c 96 d2 16 82 ca f9 43 cf 31 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        3 of ($proc_hash_*)
}
