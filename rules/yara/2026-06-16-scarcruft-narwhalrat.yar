/*
 * ScarCruft APT37 NarwhalRAT Campaign - YARA Rules
 * Generated: 2026-06-16 | Version: 1.1 (FINAL)
 * Source: https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat
 */

rule APT37_NarwhalRAT_Python_Payload
{
    meta:
        description = "Detects NarwhalRAT compiled Python payload used by ScarCruft APT37"
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat"
        hash_md5_1 = "3715092aa00f380cefe8b4d2eddb7d08"
        hash_md5_2 = "7cef19f9c4480adac0cd4702ff98f46c"
        hash_md5_3 = "7eb9cee1f696727752169f25cf79a338"
        hash_md5_4 = "b6b0602310bb2d4360c52685119aac1b"
        tlp = "WHITE"
        confidence = "high"

    strings:
        $cmd_startkcap = "startkcap:" ascii
        $cmd_endkcap = "endkcap:" ascii
        $cmd_startscap = "startscap:" ascii
        $cmd_endscap = "endscap:" ascii
        $cmd_startscaph = "startscaph:" ascii
        $cmd_endscaph = "endscaph:" ascii
        $cmd_startlcap = "startlcap:" ascii
        $cmd_endlcap = "endlcap:" ascii
        $cmd_usb2local = "usb2local:" ascii
        $cmd_cmserver = "cmserver:" ascii
        $cmd_caserver = "caserver:" ascii
        $cmd_cdserver = "cdserver:" ascii
        $cmd_chcommpwd = "chcommpwd:" ascii
        $cmd_cmdadm = "cmdadm:" ascii
        $dir_naverwhale = "naverwhale" ascii wide
        $mutex = "i5zJH9FL10cVd3sSW9eyWWErPJ" ascii wide
        $aes_key = "!221aeAescde##2aefseseppl^12" ascii

    condition:
        (3 of ($cmd_*)) or
        ($mutex) or
        ($aes_key) or
        ($dir_naverwhale and 2 of ($cmd_*)) or
        (5 of them)
}

rule APT37_NarwhalRAT_LNK_Dropper
{
    meta:
        description = "Detects malicious LNK files used to deliver NarwhalRAT by ScarCruft APT37"
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat"
        tlp = "WHITE"
        confidence = "high"

    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $cmd_pattern1 = "cmd /k" ascii nocase
        $bat_name = "KHjWFcsE.bat" ascii
        $temp_zip = "temp012.zip" ascii
        $task_name = "MicrosoftUserInterfacePicturesUpdateTackMachine" ascii
        $userscreen = "userscreen.exe" ascii
        $config_cat = "config.cat" ascii
        $decoy_hwp = "Cybersecurity Advisory Notice" ascii wide
        $path_public = "C:\\Users\\Public\\AccountPictures\\UserInerfacePicture" ascii nocase
        $path_appdata = "naverwhale" ascii

    condition:
        $lnk_magic at 0 and
        (
            ($bat_name) or
            ($temp_zip and $cmd_pattern1) or
            ($task_name) or
            ($userscreen and $config_cat) or
            ($path_public) or
            (3 of them)
        )
}

rule APT37_NarwhalRAT_Config_CAT
{
    meta:
        description = "Detects NarwhalRAT config.cat payload file containing encrypted Python bytecode"
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat"
        tlp = "WHITE"
        confidence = "low"

    strings:
        $pyc_magic = { 6F 0D 0D 0A }
        $import1 = "__import__" ascii
        $import2 = "getattr" ascii
        $import3 = "__builtins__" ascii
        $import4 = "ctypes" ascii
        $import5 = "CFUNCTYPE" ascii
        $api_virtualalloc = "VirtualAlloc" ascii
        $api_rtlmovemem = "RtlMoveMemory" ascii
        $api_createmutex = "CreateMutexW" ascii
        $mutex = "i5zJH9FL10cVd3sSW9eyWWErPJ" ascii
        $aes_key = "!221aeAescde##2aefseseppl^12" ascii
        $narwhal_dir = "naverwhale" ascii

    condition:
        ($pyc_magic at 0 and 2 of ($import*) and ($mutex or $aes_key)) or
        (3 of ($api_*) and 2 of ($import*) and ($mutex or $aes_key or $narwhal_dir)) or
        ($mutex and $aes_key)
}
