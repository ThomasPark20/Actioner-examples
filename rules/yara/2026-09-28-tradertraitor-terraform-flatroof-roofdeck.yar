rule FLATROOF_macOS_Backdoor
{
    meta:
        description = "Detects FLATROOF (macOS.Gaslight) ARM64 Rust-based backdoor deployed by TraderTraitor DPRK actors"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        hash_sha1 = "02df07a173ab03b82a4fb6a08973fff8b1467f28"
        threat_actor = "TraderTraitor"
        malware_family = "FLATROOF"
        macho_caveat = "Mach-O magic at offset 0 matches thin binaries only; FAT/Universal (0xCAFEBABE/0xBEBAFECA) require FAT header parsing to reach embedded slices"

    strings:
        $mach_header = { CF FA ED FE }
        $s1 = "SystemUpdate" ascii
        $s2 = "technicais.sytes.net" ascii
        $s3 = "tmp.lock" ascii
        $s4 = "com.apple.iTunesCloud" ascii
        $rust1 = "rustc" ascii
        $pipe = ".pipe-airway" ascii

    condition:
        $mach_header at 0 and
        $rust1 and
        3 of ($s1, $s2, $s3, $s4, $pipe)
}

rule ROOFDECK_macOS_Backdoor
{
    meta:
        description = "Detects ROOFDECK ARM64 Rust-based backdoor with Nostr relay C2, deployed by TraderTraitor DPRK actors"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        hash_sha1_isync = "c491d477dbe0ae04e9aed9dbe237144c03f73ec4"
        hash_sha1_loginwindow = "5728b11d30586bbfc1d8bd12df1c722a06e767a2"
        threat_actor = "TraderTraitor"
        malware_family = "ROOFDECK"
        macho_caveat = "Mach-O magic at offset 0 matches thin binaries only; FAT/Universal (0xCAFEBABE/0xBEBAFECA) require FAT header parsing to reach embedded slices"

    strings:
        $mach_header = { CF FA ED FE }
        $s1 = "app_version" ascii
        $s2 = "hubpage.cloud" ascii
        $s3 = "grenight.com" ascii
        $s4 = ".repl_history" ascii
        $s5 = "com.apple.internal.ck" ascii
        $s6 = "com.apple.appleaccountd" ascii
        $nostr1 = "relay.damus.io" ascii
        $nostr2 = "nos.lol" ascii
        $nostr3 = "nostr.mom" ascii
        $nostr4 = "relay.snort.social" ascii
        $rust1 = "rustc" ascii
        $pipe = ".pipe-airway" ascii

    condition:
        $mach_header at 0 and
        $rust1 and
        (
            2 of ($nostr1, $nostr2, $nostr3, $nostr4) or
            3 of ($s1, $s2, $s3, $s4, $s5, $s6, $pipe)
        )
}

rule TraderTraitor_Terraform_LockFile_Poisoned
{
    meta:
        description = "Detects weaponized Terraform lock files referencing malicious HashiCorp-impersonating registries used by TraderTraitor"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/"
        threat_actor = "TraderTraitor"

    strings:
        $reg1 = "registry.hashicorp-aws.com" ascii nocase
        $reg2 = "registry.hashicorp-aws.io" ascii nocase
        $reg3 = "registry.hashicorp-terraform.io" ascii nocase
        $tf_ctx1 = "provider" ascii
        $tf_ctx2 = "h1:" ascii

    condition:
        filesize < 1MB and
        any of ($reg*) and
        any of ($tf_ctx*)
}
