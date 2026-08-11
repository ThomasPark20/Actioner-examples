rule Ransomware_DeadLock_Encryptor
{
    meta:
        description = "Detects DeadLock ransomware encryptor via distinctive footer magic marker, ransom note patterns, and configuration artifacts"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/"
        hash = "a1fdf65020ce4a0f0940c793c6425baf8a0b994ec48b9baaf72788661a9d29f4"
        severity = "critical"

    strings:
        $magic = "dDlK" ascii
        $note1 = "HOW_RECOVER" ascii wide
        $note2 = "RECOVERY_CHAT" ascii wide
        $ext = ".dlock" ascii wide
        $wallpaper_msg = "DeadLocked" ascii wide
        $contract1 = "0x8EF7c3e531d871D3B9D559722DE77EB1dEc19dAe" ascii
        $contract2 = "0x757984507c82c8dA1d3969c535dB5706eEE6426C" ascii
        $rpc1 = "polygon-bor-rpc.publicnode.com" ascii
        $rpc2 = "polygon.drpc.org" ascii
        $rpc3 = "polygon-rpc.com" ascii
        $rpc4 = "polygon.meowrpc.com" ascii
        $func1 = "0x933a9ce8" ascii
        $func2 = "0xd4070542" ascii
        $opkey = { 03 bf 50 bb f9 7c 4e 95 1e 66 ff 12 b6 89 a3 7a 3c e6 75 b4 92 1e 25 4e ae 76 da 77 57 38 43 e4 a9 }

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        filesize < 10MB and
        (
            ($magic and $ext and 1 of ($note*)) or
            (1 of ($contract*) and 1 of ($rpc*, $func*)) or
            ($opkey) or
            ($wallpaper_msg and $ext and 1 of ($note*))
        )
}
