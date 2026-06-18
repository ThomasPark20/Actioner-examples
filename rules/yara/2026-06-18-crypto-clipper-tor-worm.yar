rule Malware_CryptoBandits_Worm_Strings
{
    meta:
        description = "Detects CryptoBandits crypto clipper worm via characteristic C2 endpoint strings, action keywords, and Tor proxy usage patterns"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        severity = "critical"

    strings:
        $c2_route = "/route.php" ascii wide
        $c2_recvf = "/recvf.php" ascii wide
        $c2_stub = "/stub.php" ascii wide

        $action_seed = "SEED" ascii wide
        $action_pkey = "PKEY" ascii wide
        $action_repl = "REPL" ascii wide
        $action_guid = "GUID" ascii wide
        $action_good = "GOOD" ascii wide
        $action_eval = "EVAL" ascii wide

        $socks_proxy = "socks5-hostname" ascii wide
        $tor_port = "localhost:9050" ascii wide
        $tor_port2 = "127.0.0.1:9050" ascii wide

        $onion1 = "cgky6bn6ux5wvlybtmm3z255igt52ljml2ngnc5qp3cnw5jlglamisad.onion" ascii wide
        $onion2 = "gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion" ascii wide
        $onion3 = "he5vnov645txpcv57el2theky2elesn24ebvgwfoewlpftksxp4fnxad.onion" ascii wide
        $onion4 = "lyhizqy2js2eh6ufngkbzntouiikdek5zsdj3qwa22b4z6knpqorgiad.onion" ascii wide
        $onion5 = "j3bv7g27oramhbxxuv6gl3dcyfmf44qnvju3offdyrap7hurfprq74qd.onion" ascii wide
        $onion6 = "shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion" ascii wide
        $onion7 = "7goms4byw26kkbaanz5a5u5234gusot7rp5imzc3ozh66wwcvmcudjid.onion" ascii wide
        $onion8 = "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion" ascii wide
        $onion9 = "wt26llpl5k6gok3vnaxmucwgzv2wk3l7nuibbh25clghrtus3p5ctsid.onion" ascii wide
        $onion10 = "ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion" ascii wide

    condition:
        filesize < 10MB and
        (
            (2 of ($c2_*) and 2 of ($action_*)) or
            (1 of ($c2_*) and 1 of ($socks_proxy, $tor_port, $tor_port2) and 1 of ($action_*)) or
            2 of ($onion*)
        )
}

rule Malware_CryptoBandits_Worm_Artifacts
{
    meta:
        description = "Detects CryptoBandits worm samples by artifact strings and cryptocurrency address regex patterns embedded in the binary"
        author = "Actioner"
        date = "2026-06-18"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"
        hash = "7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c"
        severity = "critical"

    strings:
        $ugate = "ugate.exe" ascii wide nocase
        $public_docs = "\\Users\\Public\\Documents\\" ascii wide
        $cfile = "cfile" ascii fullword

        $crypto_btc_legacy = "^1[a-km-zA-HJ-NP-Z1-9]{25,34}$" ascii
        $crypto_btc_p2sh = "^3[a-km-zA-HJ-NP-Z1-9]{25,34}$" ascii
        $crypto_btc_bech32 = "^bc1q[a-z0-9]{38,62}$" ascii
        $crypto_btc_taproot = "^bc1p[a-z0-9]{38,62}$" ascii
        $crypto_tron = "^T[a-km-zA-HJ-NP-Z1-9]{33}$" ascii
        $crypto_monero = "^[48][0-9AB][a-zA-Z0-9]{93}$" ascii

    condition:
        filesize < 10MB and
        (
            ($ugate and $public_docs) or
            ($ugate and 2 of ($crypto_*)) or
            ($public_docs and $cfile and 1 of ($crypto_*)) or
            (3 of ($crypto_*) and $cfile and $public_docs)
        )
}
