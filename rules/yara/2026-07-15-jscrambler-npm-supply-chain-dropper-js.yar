rule Supply_Chain_jscrambler_IronWorm_Dropper_JS
{
    meta:
        description = "Detects the setup.js dropper script from compromised jscrambler npm package using distinctive spawn and extension obfuscation patterns"
        author = "Actioner"
        date = "2026-07-15"
        reference = "https://safedep.io/jscrambler-npm-supply-chain-compromise/"
        hash = "a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60"
        severity = "critical"

    strings:
        $fromcharcode = "String.fromCharCode(46,101,120,101)" ascii
        $detached = "detached" ascii
        $windowshide = "windowsHide" ascii
        $stdio_ignore = "stdio" ascii
        $intro = "intro.js" ascii

    condition:
        filesize < 50KB and
        $fromcharcode and
        2 of ($detached, $windowshide, $stdio_ignore, $intro)
}
