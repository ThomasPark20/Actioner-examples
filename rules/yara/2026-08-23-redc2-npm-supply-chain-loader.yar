rule Malware_RedC2_RedShell_NPM_Loader
{
    meta:
        description = "Detects the trojanized npm package loader (dist/index.mjs) that re-exports date helpers and launches a bundled RedC2 RedShell implant binary as a detached background process"
        author = "Actioner"
        date = "2026-08-23"
        reference = "https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html"
        severity = "high"

    strings:
        $bin1 = "math-core.bin" ascii
        $bin2 = "math-calc.bin" ascii
        $bin3 = "calc-math.dat" ascii
        $bin4 = "calc-cache.bin" ascii
        $bin5 = "calc-mapping.bin" ascii

        $exec1 = "chmod" ascii
        $exec2 = "spawn" ascii
        $exec3 = "detached" ascii
        $exec4 = "execSync" ascii
        $exec5 = "child_process" ascii

        $streak1 = "streak-metrics" ascii
        $streak2 = "streak-map" ascii
        $streak3 = "streak-calc" ascii
        $streak4 = "streak-cache" ascii
        $streak5 = "streak-kit" ascii
        $streak6 = "kit-map-vim" ascii

    condition:
        filesize < 5MB and
        (
            (1 of ($bin*) and 3 of ($exec*)) or
            (1 of ($bin*) and 1 of ($streak*)) or
            (2 of ($streak*) and 1 of ($exec*))
        )
}
