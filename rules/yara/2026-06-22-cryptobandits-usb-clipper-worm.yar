rule CryptoBandits_Clipper_JS_Strings
{
    meta:
        description = "Detects CryptoBandits crypto clipper JavaScript payload via distinctive C2 endpoint paths, action codes, and Tor proxy arguments"
        author = "Actioner"
        date = "2026-06-22"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        severity = "high"

    strings:
        $c2_route = "/route.php" ascii wide
        $c2_recv = "/recvf.php" ascii wide
        $c2_stub = "/stub.php" ascii wide
        $act_seed = "SEED" ascii
        $act_pkey = "PKEY" ascii
        $act_repl = "REPL" ascii
        $act_eval = "EVAL" ascii
        $socks = "socks5-hostname" ascii wide
        $proxy = "localhost:9050" ascii wide
        $tor_bin = "ugate.exe" ascii wide

    condition:
        filesize < 5MB and
        (
            (2 of ($c2_*) and 2 of ($act_*)) or
            ($tor_bin and $socks and $proxy) or
            (3 of ($c2_*) and $socks)
        )
}

rule CryptoBandits_Clipper_Hashes
{
    meta:
        description = "Detects known CryptoBandits crypto clipper samples by matching known internal strings"
        author = "Actioner"
        date = "2026-06-22"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        hash1 = "7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c"
        hash2 = "a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630"
        hash3 = "23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43"
        hash4 = "cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30"
        hash5 = "100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8"
        hash6 = "d14b80cbd1a19d4ad0473a0661297f8fdf598e81ff6c4ab24e212dcad2e54b3f"
        hash7 = "9d90f54ae36c6c5435d5b8bed40faf54cc91f6db28574a6310b5ffaeb0362e96"
        hash8 = "67fc5cf395e28294bbb91ed0e954fdf2e80ebd9119022a115a42c286dc8bacf5"
        hash9 = "0020d23b0f9c5e6851a7f737af73fd143175ee47054931166369edd93338538a"
        hash10 = "35a6bc44b176a050fd6824904b7604f0f45b0fdfa26bf9500b9e05973b387cfd"
        hash11 = "c824630154ac4fdfce94ded01f037c305eab51e9bef3f493c60ff3184a640502"
        hash12 = "d43bf94f0cb0ab97c88113b7e07d1a4024d1610617b5ad05882b1dbab89e15ba"
        hash13 = "b2777b73a4c33ac6a409d475057843be6b5d32262ef28a1f1ff5bb52e3834c5f"
        hash14 = "7787a9a7d8ae393aa32f257d083903c4dc9b97a1e5b0458c4cd480d4f3cb5b05"
        hash15 = "f3b54984caca95fd496bcfe5d7db1611b08d2f5b7d250b43b430e5d76393f9e0"
        hash16 = "20db98af3037b197c8a846dbf17b87fc6f049c3e0d9a188f9b9a74d3916dd5e1"
        severity = "critical"

    strings:
        $s1 = "route.php" ascii wide
        $s2 = "recvf.php" ascii wide
        $s3 = "ugate.exe" ascii wide
        $s4 = "socks5-hostname" ascii wide
        $s5 = "ActiveXObject" ascii wide
        $s6 = "WScript.Shell" ascii wide
        $s7 = "Win32_Process" ascii wide

    condition:
        filesize < 10MB and ($s3 or $s4) and 3 of ($s*)
}

rule CryptoBandits_LNK_USB_Worm
{
    meta:
        description = "Detects malicious LNK shortcut files used by CryptoBandits for USB worm propagation, matching WScript/CScript invocation patterns targeting Public Documents"
        author = "Actioner"
        date = "2026-06-22"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        severity = "high"

    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $wscript = "wscript" ascii wide nocase
        $cscript = "cscript" ascii wide nocase
        $public_docs = "\\Users\\Public\\Documents\\" ascii wide nocase
        $js_ext = ".js" ascii wide

    condition:
        $lnk_magic at 0 and
        filesize < 100KB and
        ($wscript or $cscript) and
        $public_docs and
        $js_ext
}
