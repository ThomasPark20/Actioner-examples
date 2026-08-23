rule Rootkit_SPECTRE_Linux_Kernel_Module
{
    meta:
        description = "Detects SPECTRE Linux rootkit kernel module (Specter/acpi_pad.ko) via ftrace hooking strings, signal-based IPC magic values, and hooked syscall handler names"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $hook1 = "hooked_tcp6_seq_show" ascii
        $hook2 = "hooked_tcp4_seq_show" ascii
        $hook3 = "hooked_tkill" ascii
        $hook4 = "hooked_tgkill" ascii
        $hook5 = "hooked_kill" ascii
        $hook6 = "hooked_getdents64" ascii
        $ftrace = "FTRACE_OPS_FL_IPMODIFY" ascii
        $mod_name = "acpi_pad" ascii
        $svc = "hardware-monitor" ascii
        $desc = "Hardware Performance Monitor" ascii
        $magic_hex = { 69 7A 00 00 }

    condition:
        (uint32(0) == 0x464C457F or $mod_name) and
        (
            (3 of ($hook*)) or
            ($ftrace and 1 of ($hook*)) or
            ($mod_name and $svc and $desc) or
            (2 of ($hook*) and $magic_hex)
        )
}
