/*
 * PerfectPioneer / KUKURAT HTTP/3 RATs — YARA Detection Rules
 * Campaign: TGR-STA-0049 targeting Southeast Asian governments
 * Reference: https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/
 * Generated: 2026-11-17 | Version: 1.1 (revised)
 * Validation: yarac exit 0
 */

rule Malware_PerfectPioneer_RAT_Strings
{
    meta:
        description = "Detects PerfectPioneer RAT variants via project path strings and C2 endpoint patterns found in Go binaries"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash = "5b7effbf0465c05e8dc9a8fea69b000a78237735ea0b854e8d9baee5b7af8344"
        severity = "high"

    strings:
        $pdb1 = "D:/proj/RatAAkk-tt/agent/" ascii
        $pdb2 = "D:/proj/PerfectRat/agent/" ascii
        $pdb3 = "D:/proj/http3/newhttp3/agent/" ascii
        $pdb4 = "D:/proj/http3/rat_http3_ls/agent/" ascii
        $pdb5 = "D:/proj/http3/Pioneer/" ascii
        $pdb6 = "D:/proj/http3/rat_http3_cc/" ascii

        $c2_1 = "/agent/register" ascii
        $c2_2 = "/agent/heartbeat" ascii
        $c2_3 = "/agent/tasks" ascii
        $c2_4 = "/agent/result" ascii

        $cmd1 = "isDangerousCommand" ascii
        $cmd2 = "file_upload" ascii
        $cmd3 = "socks5_proxy" ascii
        $cmd4 = "keylogger_start" ascii
        $cmd5 = "screenshot_capture" ascii

    condition:
        filesize < 30MB and
        (
            any of ($pdb*) or
            (3 of ($c2*) and 2 of ($cmd*))
        )
}

rule Malware_KUKURAT_RAT_Strings
{
    meta:
        description = "Detects KUKURAT RAT via module names, configuration keys, and C2 endpoint patterns"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash = "b8dca1c7e7a74ce82ab4e4cad9b718a458735d2c6c956e4cf3109aac59bfd0e4"
        severity = "high"

    strings:
        $kuku_pdb = "d:\\proj\\KUKURAT\\" ascii nocase

        $pipe = "WINDOW_SEC_WATCHDOG" ascii wide
        $hash_ep = "c8a4e192" ascii

        $mod1 = "BofLoader.dll" ascii wide
        $mod2 = "SmbBrute.dll" ascii wide
        $mod3 = "yuze_dll.dll" ascii wide
        $mod4 = "ComExec.dll" ascii wide
        $mod5 = "MyPsExec.dll" ascii wide

        $cfg1 = "set_obfuscation" ascii
        $cfg2 = "module_states" ascii
        $cfg3 = "set_heartbeat" ascii
        $cfg4 = "set_silent" ascii
        $cfg5 = "set_runtime_config" ascii

        $cmd1 = "bypass_uac" ascii
        $cmd2 = "elevate_privilege" ascii
        $cmd3 = "load_module" ascii
        $cmd4 = "unload_module" ascii
        $cmd5 = "process_inject" ascii

    condition:
        filesize < 30MB and
        (
            $kuku_pdb or
            ($pipe and $hash_ep) or
            (2 of ($mod*) and 2 of ($cfg*)) or
            (3 of ($cmd*) and 2 of ($cfg*))
        )
}

rule Malware_KUKURAT_PsExecService
{
    meta:
        description = "Detects the custom PsExecService module deployed by KUKURAT for lateral movement"
        author = "Actioner"
        date = "2026-11-17"
        reference = "https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/"
        hash = "34cc9bc4a533b91e7cdb30fecc57ba609dc890780fd13ecfbc253047b3b37b78"
        severity = "high"

    strings:
        $pdb = "d:\\proj\\KUKURAT\\modules\\MyPsExec-master\\PsExecService\\" ascii
        $pipe = "\\\\.\\pipe\\PSEXEC" ascii wide
        $svc = "PsExec" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ($pdb or ($pipe and $svc))
}
