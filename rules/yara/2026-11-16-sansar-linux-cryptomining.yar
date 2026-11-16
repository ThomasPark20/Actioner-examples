/*
 * SANSAR Linux Cryptomining Toolkit (REF3364) - YARA Detection Rules
 * Source: Elastic Security Labs + Actioner automated analysis
 * Date: 2026-11-16
 */

rule SANSAR_Orchestrator {
    meta:
        description = "Detects the SANSAR Rust-based cryptomining orchestrator used by REF3364"
        author = "Actioner"
        date = "2026-11-16"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        hash = "00c9ac44291f83c72d54302e99d155a3e26d02225a3e516764d5833a99657c9e"
    strings:
        $s1 = "TracerPid" ascii
        $s2 = "/proc/self/status" ascii
        $s3 = "client_id" ascii
        $s4 = "MinerStart" ascii
        $s5 = "MinerStop" ascii
        $s6 = "MinerConfigUpdate" ascii
        $s7 = "ShellOpen" ascii
        $s8 = "ShellData" ascii
        $s9 = "StressStart" ascii
        $s10 = "StressStop" ascii
        $s11 = "BridgeUpdate" ascii
        $s12 = "--norc" ascii
        $s13 = "--noprofile" ascii
        $s14 = "HISTFILE" ascii
        $s15 = "nvidia-smi" ascii
        $s16 = "GpuWildrig" ascii
        $s17 = "CpuXmrig" ascii
        $rust = "rustc" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 20MB and
        $rust and
        8 of ($s*)
}

rule SANSAR_NVML_Hook {
    meta:
        description = "Detects the modified NVML wrapper library used by SANSAR to falsify GPU telemetry"
        author = "Actioner"
        date = "2026-11-16"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        hash = "675c24728f87f7aa0fa07527027c95c24c246049c65eaef89270ab04ea50a180"
    strings:
        $nvml1 = "nvmlDeviceGetUtilizationRates" ascii
        $nvml2 = "nvmlDeviceGetTemperature" ascii
        $nvml3 = "nvmlDeviceGetPowerUsage" ascii
        $nvml4 = "nvmlDeviceGetComputeRunningProcesses" ascii
        $backup = ".libnvidia-ml.so.1.backup" ascii
        $hook = "nvml_hook" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        $backup and
        $hook and
        3 of ($nvml*)
}

rule SANSAR_Rootkit_acpi_thermal_mgr {
    meta:
        description = "Detects the acpi_thermal_mgr ftrace-based rootkit kernel module used by REF3364"
        author = "Actioner"
        date = "2026-11-16"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        hash = "6ba1aa275e0e2826e8b48b36473539ca56cbdc41f429e539a45f8532b084d7a4"
    strings:
        $mod = "acpi_thermal_mgr" ascii
        $ftrace = "ftrace" ascii
        $hide1 = "hide_name" ascii
        $hide2 = "hide_prefix" ascii
        $hide3 = "hide_module" ascii
        $proc = "/proc" ascii
        $getdents = "getdents" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 2MB and
        $mod and
        $ftrace and
        $proc and
        2 of ($hide*) and
        $getdents
}

rule SANSAR_Netns_Backdoor {
    meta:
        description = "Detects the netns Ethereum-assisted backdoor used by REF3364"
        author = "Actioner"
        date = "2026-11-16"
        reference = "https://www.elastic.co/security-labs/threat-command/sansar-linux-cryptomining-malware"
        hash = "df8ab6fd699e6ae90e63e9696bae8f01342708bafc2ed88af414337e4f237194"
    strings:
        $eth_call = "eth_call" ascii
        $contract = "0x43eb291f56688c63c93e8a93c4591fc997cf6349" ascii nocase
        $selector = "0x6ded96e7" ascii nocase
        $shell_cmd = "SHELL " ascii
        $port = "8080" ascii
    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        ($contract or $selector) and
        ($eth_call or $shell_cmd) and
        $port
}
