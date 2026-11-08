rule ARTEX_Probe_File_Artifact
{
    meta:
        description = "Detects the ARTEX SMB reconnaissance probe file artifact (artex_probe_11876.txt) written by the framework's test scripts during network scanning"
        author = "Actioner"
        date = "2026-11-08"
        reference = "https://securityaffairs.com/202607/ai/inside-artex-ai-hacking-tools-exposed-servers-and-south-korean-bank-breaches.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $probe = "artex_probe_11876" ascii wide nocase

    condition:
        $probe
}
