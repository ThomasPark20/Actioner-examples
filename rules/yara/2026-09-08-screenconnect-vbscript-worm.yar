rule ScreenConnect_Worm_VBScript_Stager
{
    meta:
        description = "Detects later-stage VBScript stagers from the September 2026 ScreenConnect worm campaign that reference staging filenames and final payload names (PyTorchFix.ps1 or WindowsServiceHost.vbs). Early stagers lacking payload references require other detection rules."
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://www.huntress.com/blog/rogue-screenconnect-installations"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $staging_value = "value.txt" ascii wide
        $staging_map = "map.txt" ascii wide
        $staging_out = "out.enc" ascii wide
        $staging_runner = "runner.ps1" ascii wide

        $payload_pytorchfix = "PyTorchFix.ps1" ascii wide
        $payload_windowsservicehost = "WindowsServiceHost.vbs" ascii wide

        $wscript_shell = "WScript.Shell" ascii wide
        $createobject = "CreateObject" ascii wide
        $scripting_fso = "Scripting.FileSystemObject" ascii wide

        $abort_check = "abort" ascii wide

    condition:
        filesize < 500KB and
        2 of ($staging*) and
        1 of ($payload*) and
        $wscript_shell and
        $createobject and
        ($scripting_fso or $abort_check)
}

rule ScreenConnect_Worm_WindowsServiceHost_VBS
{
    meta:
        description = "Detects the WindowsServiceHost.vbs persistence payload used in the September 2026 ScreenConnect worm campaign"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://www.huntress.com/blog/rogue-screenconnect-installations"
        hash = "ffd6d23f579571cc61936145791975da78b6ae914d780a9447a8f53c3688a0de"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $name = "WindowsServiceHost" ascii wide
        $vbs_ext = ".vbs" ascii wide
        $bat_ext = ".bat" ascii wide
        $run_key = "CurrentVersion\\Run" ascii wide
        $wscript = "WScript" ascii wide
        $shell = "Shell" ascii wide

    condition:
        filesize < 100KB and
        $name and
        $run_key and
        $wscript and
        ($bat_ext or $vbs_ext) and
        $shell
}

rule ScreenConnect_Worm_PyTorchFix_PS1
{
    meta:
        description = "Detects the PyTorchFix.ps1 PowerShell payload used in the September 2026 ScreenConnect worm campaign, which performs UAC bypass, AMSI bypass, Defender exclusion, and concealed ScreenConnect installation"
        author = "Actioner"
        date = "2026-09-08"
        reference = "https://www.huntress.com/blog/rogue-screenconnect-installations"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $amsi_bypass = "amsiInitFailed" ascii wide nocase
        $uac_bypass_settings = "ms-settings" ascii wide
        $uac_bypass_exe = "ComputerDefaults.exe" ascii wide nocase
        $defender_exclusion = "Add-MpPreference" ascii wide nocase
        $exclusion_path = "ExclusionPath" ascii wide nocase
        $screenconnect_id = "7a4d7d66502d4260" ascii wide
        $password_exe = "Password.exe" ascii wide
        $sys_cache = "sys_cache.zip" ascii wide
        $svcdrv = "svcdrv64.sys" ascii wide
        $hvci_disable = "HypervisorEnforcedCodeIntegrity" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            $screenconnect_id or
            ($amsi_bypass and ($uac_bypass_settings or $uac_bypass_exe)) or
            ($defender_exclusion and $exclusion_path and 1 of ($sys_cache, $svcdrv, $password_exe)) or
            4 of them
        )
}
