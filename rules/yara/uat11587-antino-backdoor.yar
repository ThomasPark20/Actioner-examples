import "pe"

rule APT_UAT11587_Antino_Backdoor
{
    meta:
        description = "Detects UAT-11587 Antino Rust backdoor via PDB paths, PE export, manifest ID, and source path artifacts"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $pdb1 = "antino\\target\\" ascii
        $pdb2 = "slc_template.pdb" ascii
        $pdb3 = "antino_client_template.pdb" ascii

        $src1 = "antino\\client\\src\\core.rs" ascii
        $src2 = "antino\\shared\\src\\command_client.rs" ascii
        $src3 = "antino\\shared\\src\\command\\add_to_run.rs" ascii
        $src4 = "antino\\client\\src\\artillery\\run.rs" ascii
        $src5 = "antino\\client\\src\\signaller\\mod.rs" ascii
        $src6 = "antino\\shared\\src\\command\\load.rs" ascii

        $manifest = "AntinoApp" ascii wide

        $cmd1 = "command_req_" ascii wide
        $cmd2 = "command_res_" ascii wide
        $cmd3 = "antino_downloads" ascii wide
        $cmd4 = "antino_uploads" ascii wide
        $cmd5 = "/antino/heartbeats/" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            any of ($pdb*) or
            2 of ($src*) or
            ($manifest and 1 of ($cmd*)) or
            (pe.exports("SLOpen") and 2 of ($cmd*)) or
            3 of ($cmd*)
        )
}

rule APT_UAT11587_TestAssembly_Downloader
{
    meta:
        description = "Detects UAT-11587 TestAssembly.dll downloader via invariant AssemblyAttribute GUID b2b3adb0-1669-4b94-86cb-6dd682ddbea3"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "d753a615aedf8e58ffc75b2b7ebd320c0cbe6bcb5cbb885db749a2a85c55d3bf"
        tlp = "WHITE"
        severity = "high"

    strings:
        $guid_ascii = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase
        $guid_wide = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" wide nocase

        $dotnet1 = "TestAssembly" ascii wide
        $dotnet2 = "GatherOsState" ascii wide
        $dotnet3 = "GatherOSStateKit" ascii wide

    condition:
        ($guid_ascii or $guid_wide) and 1 of ($dotnet*)
}

rule APT_UAT11587_HTA_Stager
{
    meta:
        description = "Detects UAT-11587 HTA stager via hardcoded tracking beacon domain and Cloudflare infrastructure patterns"
        author = "Actioner"
        date = "2026-09-30"
        reference = "https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/"
        hash = "e809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34"
        tlp = "WHITE"
        severity = "high"

    strings:
        $beacon = "oisadjfoinsiduhfnoisdnfosdnoifnsoid" ascii nocase
        $track = "?track" ascii
        $r2 = ".r2.dev" ascii nocase
        $cf_pages = ".pages.dev" ascii nocase
        $hta_marker1 = "<HTA:APPLICATION" ascii nocase
        $hta_marker2 = "mshta" ascii nocase

    condition:
        filesize < 1MB and
        $beacon and
        ($track or $r2 or $cf_pages) and
        (1 of ($hta_marker*))
}
