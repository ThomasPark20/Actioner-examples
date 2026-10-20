rule OVHcloud_CLI_Malicious_Binary {
    meta:
        description = "Detects the malicious OVHcloud CLI binary from the October 2026 supply chain compromise based on build metadata strings"
        author = "Detection Engineering"
        date = "2026-10-20"
        reference = "https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool"
        hash = "3833daffcaaaab27e4e0e0833240ffcb1df8df648f4ec0bc4a75c176e28933cb"
    strings:
        $pseudo_version = "v0.15.1-0.20261013083505-5ead8ef9b43d" ascii
        $vcs_rev = "5ead8ef9b43d354dfb5caadff803b11afc8c5c58" ascii
        $module = "github.com/ovh/ovhcloud-cli" ascii
        $dirty = "+dirty" ascii
    condition:
        uint32(0) == 0x464c457f and $module and $vcs_rev and $dirty and $pseudo_version
}

rule GlassWorm_Loader_AES_Key {
    meta:
        description = "Detects GlassWorm preinstall.js loader by AES-256-CBC key and IV used in the OVHcloud CLI supply chain attack"
        author = "Detection Engineering"
        date = "2026-10-20"
        reference = "https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool"
        hash = "43df42fd79f6f81e530892b54634598770d6e496796a863c596e616bcb3fec70"
    strings:
        $aes_key = "zetqHyfDfod88zloncfnOaS9gGs90ONX" ascii wide
        $aes_iv = "a041fdaa0521fb5c3e26b217aaf24115" ascii wide
        $eval = "eval" ascii wide
    condition:
        filesize < 500KB and $aes_key and ($aes_iv or $eval)
}

rule GlassWorm_Solana_DeadDrop {
    meta:
        description = "Detects the Solana wallet address used as a dead-drop resolver by GlassWorm in the OVHcloud CLI attack"
        author = "Detection Engineering"
        date = "2026-10-20"
        reference = "https://opensourcemalware.com/blog/glassworm-hacks-ovh-clouds-cli-tool"
    strings:
        $wallet = "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC" ascii wide
    condition:
        $wallet
}
