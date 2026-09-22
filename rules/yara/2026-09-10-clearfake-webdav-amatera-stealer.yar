import "pe"

rule Malware_Amatera_Stealer_Config : ClearFake
{
    meta:
        description = "Detects Amatera Stealer configuration artifacts including the XOR key, dead-drop resolver pattern, and GetEndpoints C2 command strings"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        severity = "high"
        tlp = "WHITE"

    strings:
        $xor_key = "852149723" ascii
        $deadrop1 = "telegra.ph" ascii wide
        $deadrop2 = "GetEndpoints" ascii wide
        $ver = "4.1.5-alpha" ascii
        $cfg1 = "moor" ascii fullword
        $cfg2 = "CfgInspectModuleData" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ($xor_key or ($ver and 1 of ($cfg*)) or (1 of ($deadrop*) and 1 of ($cfg*)))
}

rule Malware_ClearFake_NativeAOT_Loader : ClearFake
{
    meta:
        description = "Detects the NativeAOT loader DLL (secur32.dll) used in the ClearFake campaign for DLL side-loading via Chrome components, targeting process injection into explorer.exe"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        hash = "279d04c0cfd700c8bcb9acbed528131d3ffef8e25d12713e8649772739aecb92"
        severity = "high"
        tlp = "WHITE"

    strings:
        $s1 = "platform_experience_helper" ascii wide
        $s2 = "secur32" ascii wide
        $api1 = "VirtualAllocEx" ascii fullword
        $api2 = "WriteProcessMemory" ascii fullword
        $api3 = "NtCreateThreadEx" ascii fullword
        $api4 = "ZwTerminateProcess" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ($s1 and (1 of ($s*) and 2 of ($api*)))
}

rule Malware_NetSupport_ClearFake_Config : ClearFake
{
    meta:
        description = "Detects the NetSupport Manager configuration file (client32.ini) with the specific license serial and gateway used in the ClearFake campaign"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        hash = "bd36f4c15fe0acb6748da5ed12e45dcc37d412385812c078d1e4f04730e9f69b"
        severity = "high"
        tlp = "WHITE"

    strings:
        $serial = "NSM789508" ascii wide nocase
        $license = "KAKAN" ascii wide nocase
        $gw1 = "paternal-angrily.com" ascii wide
        $gw2 = "212.118.56.166" ascii

    condition:
        filesize < 100KB and
        ($serial or $license) and
        (1 of ($gw*))
}

rule Malware_GoReverseProxy_ClearFake : ClearFake
{
    meta:
        description = "Detects the Go reverse proxy binary from the ClearFake campaign that uses Yamux multiplexing over WebSocket Secure for bidirectional traffic relay"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        hash = "1819827e17f31e72d456158b6b9c90af25a65945f6f05d04a060da9f24179b25"
        severity = "high"
        tlp = "WHITE"

    strings:
        $pkg = "github.com/acr/proxy-panel/cmd/bot" ascii
        $yamux = "hashicorp/yamux" ascii
        $c2 = "dubbedmuch.cc" ascii

    condition:
        filesize < 20MB and
        ($pkg or ($yamux and $c2))
}

rule Malware_DCRCVDrv_BYOVD : ClearFake
{
    meta:
        description = "Detects the vulnerable DCRCVDrv.sys driver abused for BYOVD EDR termination in the ClearFake campaign via IOCTL 0x2205c0"
        author = "Actioner"
        date = "2026-09-10"
        reference = "https://blog.talosintelligence.com/clearfake-webdav-infection-chain/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $dev = "\\Device\\DCRCVDRV_U" wide
        $vendor1 = "MOCOMSYS" ascii wide
        $vendor2 = "DCRCV_U Driver" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $dev and 1 of ($vendor*)
}
