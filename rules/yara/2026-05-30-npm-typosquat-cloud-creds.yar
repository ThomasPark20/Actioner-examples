import "hash"

rule npm_typosquat_opensearch_vpmdhaj_stagers
{
    meta:
        description = "Matches the vpmdhaj typosquatted OpenSearch/ElasticSearch npm supply-chain stagers by known SHA256 (Gen-1 preinstall.js, Gen-2 setup.mjs, gzipped Bun stage-2 payload)"
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/"
        hash = "638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d"
        hash = "77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d"
        hash = "bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa"
    condition:
        hash.sha256(0, filesize) == "638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d" or
        hash.sha256(0, filesize) == "77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d" or
        hash.sha256(0, filesize) == "bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa"
}

rule npm_typosquat_opensearch_vpmdhaj_strings
{
    meta:
        description = "Matches vpmdhaj typosquat OpenSearch npm stager/payload by campaign-unique strings (C2 host, x.php beacon, X-Supply header, daemonize marker)"
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/"
    strings:
        $c2_host = "aab.sportsontheweb.net" ascii
        $c2_url  = "/x.php" ascii
        $hdr     = "X-Supply" ascii
        $daemon  = "__DAEMONIZED" ascii
    condition:
        $c2_host or ($hdr and ($c2_url or $daemon))
}
