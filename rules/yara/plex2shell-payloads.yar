import "hash"

rule Plex2Shell_Known_Miner_Hash
{
    meta:
        description = "Detects the known x12345 XMRig miner payload deployed via Plex2Shell exploitation"
        author = "Actioner"
        date = "2026-10-20"
        reference = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
        confidence = "high"

    condition:
        hash.sha256(0, filesize) == "b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49"
}

rule Plex2Shell_Known_Proxy_Hash
{
    meta:
        description = "Detects the known myawesomeproxy backdoor deployed via Plex2Shell exploitation"
        author = "Actioner"
        date = "2026-10-20"
        reference = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
        confidence = "high"

    condition:
        hash.sha256(0, filesize) == "e546b10aee5edc754da4f9b0baace00392257121911f630145078eafad1e6bd9"
}

rule Plex2Shell_Proxy_Strings
{
    meta:
        description = "Detects the myawesomeproxy reverse proxy tool by string patterns"
        author = "Actioner"
        date = "2026-10-20"
        reference = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
        confidence = "medium"

    strings:
        $s1 = "myawesomeproxy" ascii wide
        $s2 = "agreeing to potential use" ascii wide
        $s3 = "internet traffic" ascii wide
        $domain = "proxystream.st" ascii wide

    condition:
        uint32(0) == 0x464C457F and ($s1 or ($s2 and $s3) or $domain)
}

rule Plex2Shell_Miner_Strings
{
    meta:
        description = "Detects the mylovelyminer XMRig payload by string patterns"
        author = "Actioner"
        date = "2026-10-20"
        reference = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
        confidence = "medium"

    strings:
        $miner_name = "mylovelyminer" ascii wide
        $pool = "ota.proxystream.st" ascii wide
        $xmrig = "xmrig" ascii wide nocase

    condition:
        uint32(0) == 0x464C457F and ($miner_name or ($pool and $xmrig))
}
