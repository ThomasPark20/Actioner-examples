rule Malware_Amatera_NativeAOT_Loader_Secur32
{
    meta:
        description = "Detects the ClearFake NativeAOT sideload loader (masquerading as Secur32.dll) that decrypts and manually maps the Amatera stealer / ZigCryptoStealer chain into a suspended explorer.exe process"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        hash = "279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92"
        severity = "high"

    strings:
        $build1 = "GETWELL2" ascii
        $build2 = "GETWELLV2" ascii
        $xorkey = "852149723" ascii
        $device = "\\Device\\DCRCVDRV_U" ascii wide
        $child   = "explorer.exe" ascii wide
        $api1 = "VirtualAllocEx" ascii fullword
        $api2 = "WriteProcessMemory" ascii fullword
        $api3 = "ResumeThread" ascii fullword
        $api4 = "SetThreadContext" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            1 of ($build*) or
            $xorkey or
            $device or
            (3 of ($api*) and $child)
        )
}

rule Malware_ZigCryptoStealer_EtherHiding_Clipper
{
    meta:
        description = "Detects ZigCryptoStealer, a Zig-language clipboard-hijacking cryptocurrency clipper delivered by the ClearFake WebDAV chain that resolves its rotating C2 domain via an EtherHiding BNB Smart Chain JSON-RPC lookup"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        severity = "high"

    strings:
        $rpc      = "bsc.rpc.blxrbdn.com" ascii wide
        $contract = "0x7CC3cFC1Ac007B8c6566fD2C7419b15a75473468" ascii wide nocase
        $method   = "eth_call" ascii
        $zigrt1   = "zig_panic" ascii
        $zigrt2   = "ZigCompilerBug" ascii
        $clip1    = "CF_TEXT" ascii
        $clip2    = "GetClipboardData" ascii fullword
        $clip3    = "SetClipboardData" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            (
                $rpc or $contract or ($method and 1 of ($zigrt*))
            )
            and
            2 of ($clip*)
        )
}

rule Malware_ClearFake_DCRCVDrv_BYOVD_Driver
{
    meta:
        description = "Detects the signed but vulnerable DCRCVDrv.sys driver abused in the ClearFake chain (Bring-Your-Own-Vulnerable-Driver) to terminate EDR processes via an unauthenticated ZwTerminateProcess IOCTL"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        severity = "critical"

    strings:
        $device  = "\\Device\\DCRCVDRV_U" ascii wide
        $dosdev  = "DCRCVDRV_U" ascii wide
        $vendor1 = "MOCOMSYS" ascii wide
        $vendor2 = "DCRC" ascii wide fullword
        $ioctl   = { C0 05 22 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            ($device or $dosdev) and
            (1 of ($vendor*) or $ioctl)
        )
}
