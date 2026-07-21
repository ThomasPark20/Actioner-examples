rule ViteVenom_ChainVeil_NPM_Loader
{
    meta:
        description = "Detects ViteVenom/ChainVeil malicious npm package loader via XOR keys, obfuscator markers, and blockchain wallet addresses used for C2 resolution"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
        severity = "high"

    strings:
        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii
        $tron_wallet1 = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP" ascii
        $tron_wallet2 = "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG" ascii
        $aptos_addr1 = "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e" ascii
        $aptos_addr2 = "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3" ascii
        $obf_marker1 = "rmcej%otb%" ascii
        $obf_marker2 = "Cot%3t=shtP" ascii
        $obf_func1 = "_$_1e42" ascii
        $obf_func2 = "function MDy(f)" ascii
        $global_inject1 = "global['!']" ascii
        $global_inject2 = "global['_V']" ascii
        $api_tron = "api.trongrid.io" ascii
        $eval_call = "eval(" ascii

    condition:
        filesize < 5MB and
        (
            (any of ($xor_key*) and any of ($tron_wallet*, $aptos_addr*, $api_tron)) or
            (any of ($obf_marker*) and any of ($obf_func*, $global_inject*)) or
            (2 of ($tron_wallet*, $aptos_addr*) and $eval_call)
        )
}
