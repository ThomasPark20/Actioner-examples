rule OP512_ASPX_WebShell_FileManager
{
    meta:
        description = "Detects OP-512 ASPX web shell file manager with timestomping capability, dual C2 notification channels (DNS/HTTP), and file management operations"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $aspx_header = "<%@ Page" ascii nocase
        $timestomp1 = "SetCreationTime" ascii wide
        $timestomp2 = "SetLastWriteTime" ascii wide
        $timestomp3 = "SetLastAccessTime" ascii wide
        $fileop1 = "Directory.GetFiles" ascii wide
        $fileop2 = "File.Delete" ascii wide
        $fileop3 = "File.Move" ascii wide
        $fileop4 = "File.WriteAllBytes" ascii wide
        $dns1 = "DnsGetRecord" ascii wide
        $dns2 = "nslookup" ascii wide nocase
        $http_fallback = "python-requests" ascii wide
        $c2_pattern = "hcgos.com" ascii wide nocase
        $c2_pattern2 = "lhlsjcb.com" ascii wide nocase

    condition:
        filesize < 500KB and
        $aspx_header and
        (2 of ($timestomp*)) and
        (2 of ($fileop*)) and
        (1 of ($dns*) or $http_fallback or 1 of ($c2_pattern*))
}

rule OP512_ASHX_Command_Handler
{
    meta:
        description = "Detects OP-512 ASHX command handler web shell with RSA signature verification and RC4 decryption pipeline"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512"
        tlp = "WHITE"
        severity = "high"

    strings:
        $ashx_header = "<%@ WebHandler" ascii nocase
        $rsa1 = "RSACryptoServiceProvider" ascii wide
        $rsa2 = "RSAParameters" ascii wide
        $rsa3 = "VerifyData" ascii wide
        $rc4_1 = "RC4" ascii wide nocase
        $crypto1 = "FromBase64String" ascii wide
        $crypto2 = "Convert.FromBase64String" ascii wide
        $exec1 = "Process.Start" ascii wide
        $exec2 = "ProcessStartInfo" ascii wide
        $handler = "IHttpHandler" ascii wide
        $context = "HttpContext" ascii wide

    condition:
        filesize < 200KB and
        $ashx_header and
        (1 of ($rsa*)) and
        (1 of ($rc4_*) and 1 of ($crypto*)) and
        (1 of ($exec*)) and
        ($handler or $context)
}

rule OP512_WebShell_Generic_Indicators
{
    meta:
        description = "Detects generic indicators of OP-512 web shell framework including polymorphic code patterns and cryptographic command processing pipeline"
        author = "Actioner"
        date = "2026-06-06"
        reference = "https://reliaquest.com/blog/threat-spotlight-reliaquests-agentic-ai-uncovers-new-china-linked-cluster-op-512"
        tlp = "WHITE"
        severity = "high"

    strings:
        $pipe1 = "FromBase64String" ascii wide
        $pipe2 = "RSACryptoServiceProvider" ascii wide
        $pipe3 = "ProcessStartInfo" ascii wide
        $aspx = "<%@" ascii
        $ashx = "<%@ WebHandler" ascii nocase
        $c2_dom1 = "hcgos.com" ascii wide nocase
        $c2_dom2 = "lhlsjcb.com" ascii wide nocase

    condition:
        filesize < 500KB and
        ($aspx or $ashx) and
        all of ($pipe*) and
        1 of ($c2_dom*)
}
