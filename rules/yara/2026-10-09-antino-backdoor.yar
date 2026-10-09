rule Antino_Backdoor_SLC_DLL
{
    meta:
        description = "Detects the Antino backdoor (slc.dll) - a Rust-compiled implant used by UAT-11587 for M365 Graph API C2"
        author = "CTI Research Team"
        date = "2026-10-09"
        reference = "https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html"
        hash = ""
        tlp = "WHITE"
        severity = "critical"

    strings:
        // Graph API C2 strings
        $graph1 = "graph.microsoft.com" ascii wide
        $graph2 = "/me/messages" ascii wide
        $graph3 = "/me/drive" ascii wide
        $graph4 = "command_req_" ascii wide

        // Rust compilation artifacts referencing Chinese mirror
        $rust1 = "rsproxy.cn" ascii
        $rust2 = ".cargo" ascii
        $rust3 = "rustc" ascii

        // Sideloading indicators
        $side1 = "slc.dll" ascii wide
        $side2 = "GatherOsState" ascii wide

        // Antino capability strings
        $cap1 = "cmd.exe" ascii wide
        $cap2 = "powershell" ascii wide nocase
        $cap3 = "shellcode" ascii wide nocase
        $cap4 = "TestAssembly" ascii wide

        // Rust binary markers
        $pe1 = { 4D 5A }
        $rust_panic = "panicked at" ascii
        $rust_unwrap = "called `Option::unwrap()`" ascii

    condition:
        $pe1 at 0 and
        (
            ( 2 of ($graph*) and 1 of ($rust*) ) or
            ( 3 of ($graph*) and 1 of ($cap*) ) or
            ( $graph4 and $side1 and $side2 ) or
            ( 2 of ($graph*) and $rust_panic and $rust_unwrap )
        )
}

rule Antino_TestAssembly_Loader
{
    meta:
        description = "Detects the .NET deserialization loader (TestAssembly.dll) used in the Antino backdoor infection chain"
        author = "CTI Research Team"
        date = "2026-10-09"
        reference = "https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html"
        severity = "high"

    strings:
        $dotnet1 = "_CorDllMain" ascii
        $dotnet2 = "mscoree.dll" ascii
        $name = "TestAssembly" ascii wide
        $deser = "Deserialize" ascii wide
        $cloudfront = "cloudfront.net" ascii wide
        $pe = { 4D 5A }

    condition:
        $pe at 0 and
        $dotnet1 and $dotnet2 and $name and
        ( $deser or $cloudfront )
}
