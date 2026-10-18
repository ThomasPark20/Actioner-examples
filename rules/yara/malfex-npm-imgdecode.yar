rule MALFEX_imgdecode_native_addon
{
    meta:
        description = "Detects MALFEX imgdecode malicious Node.js native addon DLL with XOR-0x37 obfuscated strings and characteristic PDB path"
        author = "Actioner CTI"
        date = "2026-10-18"
        reference = "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/"
        hash1 = "d7b2f6d7da81301e7f76d6812d78f4a453439141d419831522ebf7cf5bf1c714"
        hash2 = "54d995c5be97408e96db72ecc27af1dd65716f96371df085c4ce681dca623d85"
        hash3 = "a53946269ffcd25c7fe1fad358c189f144dcca4d736f2b5a8ebc517a8d929dd1"

    strings:
        // XOR 0x37 encoded "nif-runtime-2027"
        $xor_key = { 59 5E 51 1A 45 42 59 43 5E 5A 52 1A 05 07 05 00 }

        // XOR 0x37 encoded "https://raw.gith"
        $xor_url = { 5F 43 43 47 44 0D 18 18 45 56 40 19 50 5E 43 5F }

        // XOR 0x37 encoded "WriteProcessMemo"
        $xor_wpm = { 60 45 5E 43 52 67 45 58 54 52 44 44 7A 52 5A 58 }

        // XOR 0x37 encoded "CreateRemoteThre"
        $xor_crt = { 74 45 52 56 43 52 65 52 5A 58 43 52 63 5F 45 52 }

        // PDB path from build environment
        $pdb = "C:\\Users\\Administrator\\Desktop\\npm\\imgdecode\\build\\Release\\imgdecode.pdb"

        // N-API registration export
        $napi = "napi_register_module_v1"

    condition:
        uint16(0) == 0x5A4D and
        (
            ($pdb and $napi) or
            (2 of ($xor_key, $xor_url, $xor_wpm, $xor_crt))
        )
}

rule MALFEX_Stage2_Go_Downloader
{
    meta:
        description = "Detects MALFEX Stage 2 Go downloader (svc_update.exe) that retrieves the MALFEX stealer/RAT"
        author = "Actioner CTI"
        date = "2026-10-18"
        reference = "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/"
        hash = "2f268ca76ab27971d8b16bd4ded26e1f9cd3d4460b894af2d4bdf89f0ab7ec4b"

    strings:
        $url = "http://104.234.65.75:700/setup.exe"
        $go_build = "Go build"
        $svc_update = "svc_update"

    condition:
        uint16(0) == 0x5A4D and
        $url and
        ($go_build or $svc_update)
}
