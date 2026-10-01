rule APT_UAT11587_Antino_Backdoor
{
    meta:
        description = "Detects UAT-11587 Antino Rust backdoor via distinctive PDB paths, application manifest, and C2 path strings"
        author = "Actioner"
        date = "2026-10-01"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff"
        severity = "critical"

    strings:
        $pdb1 = "\\antino\\antino\\target\\" ascii
        $pdb2 = "slc_template.pdb" ascii
        $pdb3 = "antino_client_template.pdb" ascii

        $manifest = "AntinoApp" ascii wide

        $c2path1 = "/antino/heartbeats/" ascii
        $c2path2 = "antino_downloads" ascii
        $c2path3 = "antino_uploads" ascii

        $cmd1 = "command_req_" ascii
        $cmd2 = "command_res_" ascii

        $src1 = "artillery\\run.rs" ascii
        $src2 = "signaller\\mod.rs" ascii

        $cfg_section = ".cfg" ascii fullword

        $guid = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            any of ($pdb*) or
            ($manifest and 2 of ($c2path*)) or
            (3 of ($c2path*, $cmd*)) or
            (any of ($src*) and $cfg_section) or
            $guid
        )
}

rule APT_UAT11587_TestAssembly_Downloader
{
    meta:
        description = "Detects UAT-11587 TestAssembly.dll .NET downloader used in Stage 4 of the Antino infection chain"
        author = "Actioner"
        date = "2026-10-01"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "d753a615aedf8e58ffc75b2b7ebd320c0cbe6bcb5cbb885db749a2a85c55d3bf"
        severity = "high"

    strings:
        $guid = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase
        $name = "TestAssembly" ascii wide
        $path1 = "GatherOsState.exe" ascii wide
        $path2 = "slc.dll" ascii wide
        $path3 = "Windows GatherOSStateKit" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        $guid and
        ($name or 2 of ($path*))
}
