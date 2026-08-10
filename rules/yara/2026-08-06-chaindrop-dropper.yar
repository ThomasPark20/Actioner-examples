rule Malware_ChainDrop_NPM_Worm_Dropper
{
    meta:
        description = "Detects ChainDrop npm worm dropper (setup.mjs) that downloads Bun runtime and stages the credential harvester"
        author = "Actioner"
        date = "2026-08-06"
        reference = "https://www.stepsecurity.io/blog/chaindrop-npm-worm"
        hash = "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"
        severity = "high"

    strings:
        $bun_dl = "bun-dl-" ascii
        $bun_ver = "bun-v1.3.13" ascii
        $bun_linux = "bun-linux-x64-baseline" ascii
        $bun_darwin = "bun-darwin-aarch64" ascii

        $math1 = "Math_Symbol.js" ascii
        $math2 = "math_init.js" ascii

        $dpkg = "tmp.dpkg_" ascii
        $runtime = "_NODE_RUNTIME_INIT" ascii

    condition:
        filesize < 50KB and
        (
            ($bun_ver and 1 of ($math*)) or
            (1 of ($bun_*) and $dpkg) or
            ($runtime and 1 of ($math*))
        )
}
