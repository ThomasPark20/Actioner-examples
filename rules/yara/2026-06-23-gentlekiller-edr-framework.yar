import "pe"

rule Malware_GentleKiller_EDR_Killer
{
    meta:
        description = "Detects GentleKiller EDR killer variants used by the Gentlemen RaaS operation. These PE executables load vulnerable drivers to terminate security processes at kernel level."
        author = "Actioner"
        date = "2026-06-23"
        modified = "2026-06-23"
        reference = "https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // Targeted security product process names embedded in the binary
        $proc01 = "CSFalconService.exe" ascii wide
        $proc02 = "MsMpEng.exe" ascii wide
        $proc03 = "SentinelAgent.exe" ascii wide
        $proc04 = "SentinelServiceHost.exe" ascii wide
        $proc05 = "SophosHealth.exe" ascii wide
        $proc06 = "avp.exe" ascii wide
        $proc07 = "ekrn.exe" ascii wide
        $proc08 = "cbdefense.exe" ascii wide
        $proc09 = "CylanceSvc.exe" ascii wide
        $proc10 = "cortexService.exe" ascii wide
        $proc11 = "McsAgent.exe" ascii wide
        $proc12 = "ccSvcHst.exe" ascii wide
        $proc13 = "NisSrv.exe" ascii wide

        // Vulnerable driver filenames that may be embedded as resources or strings
        $drv01 = "eb.sys" ascii wide
        $drv02 = "nseckrnl.sys" ascii wide
        $drv03 = "GameDriverX64.sys" ascii wide
        $drv04 = "stpm_old.sys" ascii wide
        $drv05 = "stpm_new.sys" ascii wide
        $drv06 = "dmx.sys" ascii wide
        $drv07 = "360netmon_wfp.sys" ascii wide
        $drv08 = "IMFForceDelete.sys" ascii wide
        $drv09 = "G11.sys" ascii wide

        // PoisonX symbolic link device path
        $dev01 = "\\\\Device\\\\{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        $dev02 = "\\\\.\\{F8284233-48F4-4680-ADDD-F8284233}" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            (5 of ($proc*) and 1 of ($drv*)) or
            (10 of ($proc*)) or
            (1 of ($dev*) and 2 of ($proc*))
        )
}

rule Malware_PoisonX_BYOVD_Driver
{
    meta:
        description = "Detects PoisonX vulnerable driver (G11.sys) used by the GentleKiller G11 variant to terminate EDR processes including CrowdStrike Falcon via kernel-mode ZwTerminateProcess."
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://threatlabsnews.xcitium.com/blog/reverse-engineering-a-0-day-poisonx-byovd-driver-bypasses-crowdstrike-edr/"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // PoisonX device symbolic link
        $dev = "{F8284233-48F4-4680-ADDD-F8284233}" ascii wide
        // Kernel APIs used for process termination
        $api1 = "ZwOpenProcess" ascii
        $api2 = "ZwTerminateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $dev and
        ($api1 and $api2)
}

rule Malware_OxideHarvest_Credential_Stealer
{
    meta:
        description = "Detects OxideHarvest (buildx641/buildx64), a Rust-based credential stealer targeting Chromium and Gecko browser stores, distributed by the Gentlemen RaaS operation."
        author = "Actioner"
        date = "2026-06-23"
        modified = "2026-06-23"
        reference = "https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/"
        tlp = "WHITE"
        severity = "low"

    strings:
        // Rust compilation artifacts
        $rust1 = ".cargo" ascii
        $rust2 = "rustc" ascii

        // OxideHarvest-specific filename strings
        $oxide1 = "buildx641" ascii wide
        $oxide2 = "buildx64" ascii wide

        // Browser credential store targets
        $browser1 = "Login Data" ascii wide
        $browser2 = "Web Data" ascii wide
        $browser3 = "Cookies" ascii wide
        $browser4 = "logins.json" ascii wide
        $browser5 = "key4.db" ascii wide
        $browser6 = "cert9.db" ascii wide

        // Chromium browser paths
        $chrome1 = "Google\\Chrome\\User Data" ascii wide
        $chrome2 = "Microsoft\\Edge\\User Data" ascii wide
        $chrome3 = "BraveSoftware\\Brave-Browser\\User Data" ascii wide
        $chrome4 = "Opera Software" ascii wide

        // Gecko browser paths
        $firefox1 = "Mozilla\\Firefox\\Profiles" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            (1 of ($oxide*) and 1 of ($rust*) and 2 of ($browser*) and 1 of ($chrome*, $firefox1)) or
            (1 of ($rust*) and 4 of ($browser*) and 3 of ($chrome*, $firefox1))
        )
}
