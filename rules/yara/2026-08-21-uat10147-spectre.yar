rule SPECTRE_Windows_Implant {
    meta:
        author = "Actioner"
        description = "Detects SPECTRE Windows implant based on debug log strings, named pipe pattern, C2 endpoints, and API hashing"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        hash = "008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2"
        severity = "critical"

    strings:
        $pipe = "\\\\.\\pipe\\spectre_" ascii wide
        $c2_register = "/api/v1/register" ascii
        $c2_output = "/api/v1/output" ascii
        $header_xid = "X-ID" ascii
        $ads_path = "\\drivers\\etc\\hosts:cache" ascii wide
        $debug1 = "spectre" ascii
        $driver1 = "RTCore64.sys" ascii wide
        $driver2 = "DBUtil_2_3.sys" ascii wide
        $hollowing_target1 = "svchost.exe" ascii wide
        $hollowing_target2 = "RuntimeBroker.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($pipe) or
            ($c2_register and $c2_output and ($header_xid or $pipe)) or
            ($ads_path and $header_xid) or
            (any of ($driver*) and any of ($hollowing_target*) and $debug1)
        )
}

rule SPECTRE_Linux_Implant {
    meta:
        author = "Actioner"
        description = "Detects SPECTRE Linux implant based on C2 endpoints, configuration patterns, and debug strings"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "critical"

    strings:
        $c2_register = "/api/v1/register" ascii
        $c2_output = "/api/v1/output" ascii
        $header_xid = "X-ID" ascii
        $debug = "spectre" ascii nocase
        $service = "hardware-monitor.service" ascii
        $rootkit_name = "acpi_pad.ko" ascii
        $magic_pid = { 69 7A 00 00 }

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            ($c2_register and $c2_output and ($header_xid or $debug)) or
            ($debug and $service) or
            ($debug and $rootkit_name) or
            ($header_xid and $c2_register and $debug) or
            ($magic_pid and $c2_register and ($header_xid or $debug))
        )
}

rule Specter_Linux_Rootkit {
    meta:
        author = "Actioner"
        description = "Detects the Specter Linux kernel rootkit module deployed by SPECTRE, based on hooked function names and IPC signals"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "critical"

    strings:
        $hook1 = "hooked_tcp6_seq_show" ascii
        $hook2 = "hooked_tcp4_seq_show" ascii
        $hook3 = "hooked_tkill" ascii
        $hook4 = "hooked_tgkill" ascii
        $hook5 = "hooked_kill" ascii
        $hook6 = "hooked_getdents64" ascii
        $ftrace = "FTRACE_OPS_FL_IPMODIFY" ascii
        $module_name = "acpi_pad" ascii
        $service = "hardware-monitor" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            (3 of ($hook*)) or
            ($ftrace and $module_name) or
            ($module_name and 2 of ($hook*)) or
            ($service and $module_name and 1 of ($hook*))
        )
}

rule SPECTRE_BYOVD_Driver_RTCore64 {
    meta:
        author = "Actioner"
        description = "Detects vulnerable RTCore64.sys driver (CVE-2019-16098) used by SPECTRE for BYOVD kernel callback tampering"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "high"

    strings:
        $driver_name = "RTCore64" ascii wide
        $msi1 = "Micro-Star" ascii wide
        $msi2 = "MICRO-STAR INTERNATIONAL" ascii wide
        $device = "\\Device\\RTCore64" ascii wide
        $symlink = "\\DosDevices\\RTCore64" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        ($device or $symlink or $driver_name) and
        (1 of ($msi*))
}

rule SPECTRE_BYOVD_Driver_DBUtil {
    meta:
        author = "Actioner"
        description = "Detects vulnerable DBUtil_2_3.sys driver (CVE-2021-21551) used by SPECTRE for BYOVD kernel callback tampering"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "high"

    strings:
        $driver_name = "DBUtil_2_3" ascii wide
        $dell1 = "Dell" ascii wide
        $dell2 = "DELL" ascii wide
        $device = "\\Device\\DBUtil" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        ($device or $driver_name) and
        (1 of ($dell*))
}

rule SPECTRE_SEO_WebShell {
    meta:
        author = "Actioner"
        description = "Detects the SeoEngineHandler ASHX web shell used by UAT-10147 for SEO fraud operations"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "high"

    strings:
        $class = "SeoEngineHandler" ascii wide
        $config = "X-seo" ascii wide
        $handler = ".ashx" ascii nocase
        $webshell1 = "sss.ashx" ascii
        $webshell2 = "up.ashx" ascii

    condition:
        filesize < 1MB and
        (
            ($class and $config) or
            ($class and $handler) or
            (all of ($webshell*))
        )
}

rule SPECTRE_NoodleRAT_Linux {
    meta:
        author = "Actioner"
        description = "Detects NoodleRAT Linux variant indicators associated with UAT-10147 campaigns, including RC4 key and staging path"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        date = "2026-08-21"
        severity = "high"

    strings:
        $rc4_key = "r0st@#$" ascii
        $staging_path = "/tmp/CCCCCCCC" ascii
        $noodle1 = "noodle" ascii nocase

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        (
            ($rc4_key and $staging_path) or
            ($rc4_key and $noodle1) or
            ($staging_path and $noodle1)
        )
}
