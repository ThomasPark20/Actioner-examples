rule SignDrop_PoC_Binary
{
    meta:
        description = "Detects the SignDrop PoC binary or close variants based on unique strings from the public exploit"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://securityaffairs.com/202968/hacking/new-signdrop-exploit-can-abuse-windows-defender-to-bypass-security-protections.html"
        reference2 = "https://www.cyderes.com/howler-cell/signdrop-zero-day"

    strings:
        $sigdrop_dir = "SigDrop_" ascii wide
        $rpc_call = "ServerMpUpdateEngineSignature" ascii wide
        $ink_path = "\\Microsoft Shared\\ink\\hid.dll" ascii wide
        $cnpf_ext = ".cnpf" ascii wide
        $mpengine = "MpEngine.dll" ascii wide
        $clfs_auth = "CLFS\\Authentication" ascii wide
        $basenamedobj = "\\BaseNamedObjects\\Restricted\\" ascii wide
        $mpasbase = "mpasbase.vdm" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($sigdrop_dir and $rpc_call) or
            ($rpc_call and $ink_path) or
            ($sigdrop_dir and $ink_path) or
            (4 of them)
        )
}

