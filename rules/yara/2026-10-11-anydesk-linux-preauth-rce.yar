rule Exploit_AnyPwn_AnyDesk_Linux_RCE
{
    meta:
        description = "Detects the AnyPwn exploit script targeting AnyDesk Linux pre-auth heap buffer overflow (mode-5 stream integer overflow to RCE)"
        author = "Actioner"
        date = "2026-10-11"
        reference = "https://github.com/v12-security/pocs/tree/main/anydesk"
        severity = "critical"

    strings:
        $tool = "anypwn" ascii nocase
        $overflow_val = "fffffff0" ascii nocase
        $port = "7070" ascii
        $arg_host = "--host" ascii
        $arg_cmd = "--command" ascii
        $heap_size = "0xf000" ascii nocase
        $groom_end = "0x17f1" ascii nocase

    condition:
        filesize < 1MB and
        $tool and $overflow_val and
        3 of them
}
