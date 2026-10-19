rule Malware_MALFEX_Imgdecode_Native_Addon
{
    meta:
        description = "Detects the MALFEX imgdecode malicious Node.js native addon (.node DLL) via PDB path, XOR key, decryption passphrase, and injection API chain"
        author = "Actioner"
        date = "2026-10-19"
        reference = "https://safedep.io/malfex-imgdecode-npm-native-addon-loader/"
        hash = "a53946269ffcd25c7fe1fad358c189f144dcca4d736f2b5a8ebc517a8d929dd1"
        hash = "d7b2f6d7da81301e7f76d6812d78f4a453439141d419831522ebf7cf5bf1c714"
        hash = "54d995c5be97408e96db72ecc27af1dd65716f96371df085c4ce681dca623d85"
        severity = "critical"

    strings:
        $pdb = "imgdecode\\build\\Release\\imgdecode.pdb" ascii
        $passphrase = "nif-runtime-2027" ascii wide
        $export = "napi_register_module_v1" ascii
        $api1 = "VirtualAllocEx" ascii fullword
        $api2 = "WriteProcessMemory" ascii fullword
        $api3 = "CreateRemoteThread" ascii fullword
        $api4 = "VirtualProtectEx" ascii fullword
        $api5 = "CreateProcessW" ascii fullword
        $target = "dllhost.exe" ascii wide
        $ua = "Mozilla/5.0" ascii
        $key = "malfexteam2027" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            $pdb or
            ($passphrase and 2 of ($api*)) or
            ($export and $passphrase) or
            ($key and 1 of ($api*)) or
            ($target and $passphrase and $ua)
        )
}
