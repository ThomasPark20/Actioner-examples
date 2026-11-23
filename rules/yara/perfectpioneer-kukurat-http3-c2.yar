rule PerfectPioneer_RAT_Go_Agent
{
    meta:
        description = "Detects PerfectPioneer RAT Go-based agent variants (RatAAkk-tt, PerfectRat, rat_http3_ls, Pioneer, newhttp3, rat_http3_cc) by matching project paths, C2 endpoint patterns, and isDangerousCommand blocklist strings"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "2281e754f70e11298db1a0a7c1b527cf2b5eec2056d4c73a46ed572ab873dc6e"
        hash2 = "f4c9d5d13c1a09533876a02f6fa04831efbf600b05cfb3ed765a0ebde82b0457"
        hash3 = "92fb9545ea49e2fb4635fce1859ff3f609738be75f85d146614243fc8bc80b67"
        hash4 = "ab06f540ecdd1d45491aa71bfc04c80852371c8f5cd43b9a6ebb53f1e1b69588"

    strings:
        // Project paths embedded in Go binaries
        $pdb1 = "D:/proj/RatAAkk-tt/agent/" ascii
        $pdb2 = "D:/proj/PerfectRat/agent/" ascii
        $pdb3 = "D:/proj/http3/newhttp3/agent/" ascii
        $pdb4 = "D:/proj/http3/rat_http3_ls/agent/" ascii
        $pdb5 = "D:/proj/http3/Pioneer/" ascii
        $pdb6 = "D:/proj/http3/rat_http3_cc/" ascii

        // C2 HTTP endpoints
        $ep1 = "/agent/register" ascii
        $ep2 = "/agent/heartbeat" ascii
        $ep3 = "/agent/tasks" ascii
        $ep4 = "/agent/result" ascii

        // isDangerousCommand blocklist (distinctive subset)
        $cmd1 = "isDangerousCommand" ascii
        $cmd2 = "cipher /w:" ascii
        $cmd3 = "crontab -r" ascii
        $cmd4 = "bcdedit" ascii
        $cmd5 = "curl | sh" ascii
        $cmd6 = "wget | bash" ascii
        $cmd7 = "powershell -enc" ascii

        // Local HTTP listener (rat_http3_cc)
        $local1 = "/info" ascii
        $local2 = "/health" ascii
        $local3 = "/status" ascii

        // C2 domains
        $c2_1 = "maui-cocktailbar" ascii
        $c2_2 = "ads-edge.com" ascii
        $c2_3 = "wkuyda.com" ascii
        $c2_4 = "thailisting.net" ascii
        $c2_5 = "yangon.it.com" ascii

    condition:
        uint16(0) == 0x5A4D and (
            any of ($pdb*) or
            (3 of ($ep*) and 2 of ($cmd*)) or
            ($cmd1 and 3 of ($cmd*)) or
            2 of ($c2*) or
            (3 of ($local*) and any of ($ep*))
        )
}

rule PerfectPioneer_Loader_DLL
{
    meta:
        description = "Detects PerfectPioneer loader DLL that side-loads from a modified legitimate binary, reads XOR-encrypted shellcode, and launches the in-memory agent"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "61f7e2f4159c566578e88cb05cdf49e4378f45ebddbd332224e97c11df922120"
        hash2 = "8cfe629fc08ae06c8ba106113ba30bb16fa2fbbf8bd3dd6831d16b031e0ebe70"

    strings:
        // XOR decryption patterns common in PE loader stubs
        $xor_loop = { 30 ?? 4? 3B ?? 72 }
        $xor_loop2 = { 32 ?? 4? 3B ?? 72 }

        // VirtualAlloc + shellcode execution pattern
        $api1 = "VirtualAlloc" ascii
        $api2 = "VirtualProtect" ascii
        $api3 = "CreateThread" ascii

        // Known C2 domains that may be embedded in loader config
        $c2_1 = "maui-cocktailbar" ascii
        $c2_2 = "ads-edge" ascii
        $c2_3 = "thailisting" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (1 of ($xor_loop*) and 2 of ($api*)) or
            1 of ($c2*)
        )
}

rule KUKURAT_RAT_CPP_Agent
{
    meta:
        description = "Detects KUKURAT modular C++ RAT by matching PDB project path, module DLL names, hashed C2 endpoints, named pipe, and configuration defaults"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "b8dca1c7e7a74ce82ab4e4cad9b718a458735d2c6c956e4cf3109aac59bfd0e4"
        hash2 = "7225ef57161cf0908560811be798d22e9354c071d576540a43aa7900784c0688"

    strings:
        // PDB / project path
        $pdb1 = "KUKURAT" ascii wide
        $pdb2 = "d:\\proj\\KUKURAT\\" ascii nocase
        $pdb3 = "MyPsExec-master\\PsExecService" ascii

        // Module DLL names
        $mod1 = "MyPsExec.dll" ascii wide
        $mod2 = "SmbBrute.dll" ascii wide
        $mod3 = "yuze_dll.dll" ascii wide
        $mod4 = "ComExec.dll" ascii wide
        $mod5 = "BofLoader.dll" ascii wide

        // Named pipe for watchdog heartbeat
        $pipe = "WINDOW_SEC_WATCHDOG" ascii wide

        // Hashed endpoint example
        $hash_ep = "/c8a4e192" ascii

        // C2 domains
        $c2_1 = "cloudflacecdn" ascii
        $c2_2 = "police.gr.com" ascii
        $c2_3 = "investigationj6" ascii

        // Configuration keys
        $cfg1 = "heartbeat_timeout_ms" ascii wide
        $cfg2 = "command_result_timeout_ms" ascii wide
        $cfg3 = "file_transfer_chunk_timeout_ms" ascii wide
        $cfg4 = "command_worker_threads" ascii wide
        $cfg5 = "module_exec_timeout_ms" ascii wide
        $cfg6 = "heartbeat_retry_before_rereg" ascii wide
        $cfg7 = "silent_mode_enabled" ascii wide
        $cfg8 = "loaded_modules" ascii wide
        $cfg9 = "module_states" ascii wide

        // Camouflage registry path
        $reg1 = "Google\\Chrome\\BrowserCrashRecovery" ascii wide
        $reg2 = "Google\\Update\\ClientState" ascii wide

        // KUKURAT capability command strings
        $cap1 = "bypass_uac" ascii wide
        $cap2 = "port_scan" ascii wide
        $cap3 = "proxy_start" ascii wide
        $cap4 = "download_module" ascii wide
        $cap5 = "process_inject" ascii wide
        $cap6 = "keylogger_start" ascii wide
        $cap7 = "powershell_execute" ascii wide
        $cap8 = "elevate_privilege" ascii wide
        $cap9 = "set_obfuscation" ascii wide
        $cap10 = "set_silent" ascii wide

    condition:
        uint16(0) == 0x5A4D and (
            any of ($pdb*) or
            3 of ($mod*) or
            ($pipe and 2 of ($cfg*)) or
            2 of ($c2*) or
            4 of ($cap*) or
            (($reg1 or $reg2) and 2 of ($cap*)) or
            ($hash_ep and $pipe)
        )
}

rule KUKURAT_Watchdog_Component
{
    meta:
        description = "Detects the KUKURAT watchdog companion binary that monitors agent health via WINDOW_SEC_WATCHDOG named pipe and relaunches the agent after 15 seconds of heartbeat silence"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "b062b4d8c19baf5c1568e28b3e0a5e2318e9501ea61ddfe804d9755c1bdbf887"

    strings:
        $pipe = "WINDOW_SEC_WATCHDOG" ascii wide
        $path = "\\ProgramData\\Cyvera\\Ransomware\\" ascii wide
        $api1 = "CreateNamedPipe" ascii
        $api2 = "ConnectNamedPipe" ascii
        $api3 = "CreateProcess" ascii

    condition:
        uint16(0) == 0x5A4D and
        $pipe and
        (1 of ($path, $api1, $api2, $api3))
}

rule KUKURAT_PsExecService_Module
{
    meta:
        description = "Detects the KUKURAT PsExecService.exe lateral movement module that opens a named pipe server (PSEXEC) with shell, upload, download, and directory listing capabilities"
        author = "Actioner"
        date = "2026-11-23"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash1 = "34cc9bc4a533b91e7cdb30fecc57ba609dc890780fd13ecfbc253047b3b37b78"

    strings:
        $pdb = "MyPsExec-master\\PsExecService" ascii
        $pipe = "\\\\.\\pipe\\PSEXEC" ascii wide nocase
        $pipe2 = "PSEXEC" ascii wide
        $svc = "PsExec" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        ($pdb or ($pipe and $svc) or ($pipe2 and $svc))
}
