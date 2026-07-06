/* PolinRider NK Supply Chain Campaign - YARA Rules
 * Date: 2026-07-06
 * Author: Actioner
 * Reference: https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
 */

rule PolinRider_Malicious_JS_Loader
{
    meta:
        description = "Detects PolinRider campaign JavaScript loaders via obfuscator markers, XOR keys, and distinctive code patterns found in malicious npm/config file injections"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands"
        tlp = "WHITE"
        severity = "high"

    strings:
        $xor_key1 = "2[gWfGj;<:-93Z^C" ascii
        $xor_key2 = "m6:tTh^D)cBz?NM]" ascii
        $obf_marker1 = "rmcej%otb%" ascii
        $obf_marker2 = "Cot%3t=shtP" ascii
        $decoder_orig = "_$_1e42" ascii
        $decoder_new = "function MDy(f)" ascii
        $global_orig = "global['!']" ascii
        $global_new = "global['_V']" ascii
        $aes_salt = "98cb54c0b4ac259d30c9c1ca1ae87c68" ascii
        $b64_npm_install = "bnBtIGluc3RhbGwgc3dpZnQtcGFyc2Utc3RyZWFtIC0tbm8tc2F2ZSAtLXNpbGVudCAtLW5vLWF1ZGl0IC0tbm8tZnVuZA==" ascii
        $c2_ip = "216.126.236.244" ascii

    condition:
        filesize < 5MB and
        (2 of ($xor_key*) or
         2 of ($obf_marker*, $decoder_orig, $decoder_new, $global_orig, $global_new) or
         $aes_salt or
         $b64_npm_install or
         ($c2_ip and 1 of ($obf_marker*, $decoder_orig, $decoder_new)))
}

rule PolinRider_Rollup_Polyfill_Masquerade
{
    meta:
        description = "Detects malicious npm packages masquerading as Rollup polyfill tools, used by Lazarus-linked actors for remote access and credential theft"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://research.jfrog.com/post/rollup-polyfill-masquerading/"
        tlp = "WHITE"
        severity = "high"

    strings:
        $pkg1 = "rollup-packages-polyfill-core" ascii
        $pkg2 = "rollup-runtime-polyfill-core" ascii
        $pkg3 = "swift-parse-stream" ascii
        $pkg4 = "quirky-token" ascii
        $pkg5 = "rollup-plugin-polyfill-connect" ascii
        $pkg6 = "react-icon-svgs" ascii
        $b64_cmd = "bnBtIGluc3RhbGw" ascii
        $spawn_hidden = "windowsHide" ascii
        $c2_endpoint = "/api/service/" ascii
        $jsonkeeper = "jsonkeeper.com" ascii
        $process_marker = "vhost.ctl" ascii

    condition:
        filesize < 2MB and
        (any of ($pkg*) and
         (1 of ($b64_cmd, $spawn_hidden, $c2_endpoint, $jsonkeeper, $process_marker)))
}

rule PolinRider_VSCode_TaskJacker
{
    meta:
        description = "Detects malicious VS Code tasks.json files used by the PolinRider TaskJacker variant to auto-execute payloads when a workspace folder is opened"
        author = "Actioner"
        date = "2026-07-06"
        reference = "https://github.com/OpenSourceMalware/PolinRider"
        tlp = "WHITE"
        severity = "low"

    strings:
        $run_on = "folderOpen" ascii
        $woff2_exec = ".woff2" ascii
        $run_on_key = "runOn" ascii
        $node_exec = "node " ascii
        $c2_vscode1 = "vscode-settings-bootstrap" ascii
        $c2_vscode2 = "vscode-bootstrapper" ascii
        $c2_vscode3 = "vscode-load-config" ascii
        $c2_vscode4 = "vscode-settings-config" ascii
        $font_path = "fa-solid-400" ascii

    condition:
        filesize < 100KB and
        $run_on and $run_on_key and
        ($woff2_exec or $font_path or ($node_exec and 1 of ($c2_vscode*)))

    /* FP note: legitimate VS Code tasks.json files using runOn:folderOpen
       exist but rarely reference .woff2 or these C2 subdomains */
}
