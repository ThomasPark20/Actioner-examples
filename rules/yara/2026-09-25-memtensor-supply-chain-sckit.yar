/*
 * YARA rules for MemTensor sckit Go-based implant detection
 * Reference: https://www.stepsecurity.io/blog/sckit-supply-chain-worm-hits-memtensor-npm-pypi-scopes
 * Reference: https://safedep.io/memtensor-sckit-worm-npm-pypi/
 */

import "hash"

rule sckit_go_implant_strings : malware supply_chain
{
    meta:
        description = "Detects the sckit Go implant by internal module path and runtime configuration strings unique to the MemTensor supply chain worm."
        author = "Actioner CTI"
        date = "2026-09-25"
        reference = "https://www.stepsecurity.io/blog/sckit-supply-chain-worm-hits-memtensor-npm-pypi-scopes"
        hash1 = "381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18"
        hash2 = "c1b0998347b489582bae7b7f4930f9831d9ef4b6bc150cfd488ee1a43272dd36"

    strings:
        $go_module = "supplychain.local/campaign/cmd/implant" ascii
        $internal_agent = "internal/agent" ascii
        $internal_wire = "internal/wire" ascii
        $config_schema = "sckit.runtime.v1" ascii
        $stage0_cmd = "sckit stage0 --config64" ascii

    condition:
        uint32(0) == 0x464c457f or  // ELF
        uint16(0) == 0x5a4d or      // MZ (PE)
        uint32(0) == 0xfeedface or  // Mach-O 32
        uint32(0) == 0xfeedfacf or  // Mach-O 64
        uint32(0) == 0xcefaedfe or  // Mach-O 32 reversed
        uint32(0) == 0xcffaedfe     // Mach-O 64 reversed
        and
        (
            $go_module or
            ($config_schema and $stage0_cmd) or
            ($internal_agent and $internal_wire and $config_schema)
        )
}

rule sckit_go_implant_campaign_ids : malware supply_chain
{
    meta:
        description = "Detects the sckit implant via campaign identifiers embedded in the binary configuration."
        author = "Actioner CTI"
        date = "2026-09-25"
        reference = "https://safedep.io/memtensor-sckit-worm-npm-pypi/"

    strings:
        $campaign_npm = "cloud-openclaw-semi-nuclear" ascii
        $campaign_pypi = "memos-semi-nuclear" ascii
        $c2_domain = "skyleen.fr" ascii

    condition:
        (
            uint32(0) == 0x464c457f or
            uint16(0) == 0x5a4d or
            uint32(0) == 0xfeedface or
            uint32(0) == 0xfeedfacf or
            uint32(0) == 0xcefaedfe or
            uint32(0) == 0xcffaedfe
        )
        and $c2_domain
        and ($campaign_npm or $campaign_pypi)
}

rule sckit_npm_package_payload : malware supply_chain
{
    meta:
        description = "Detects the malicious sckit JavaScript launcher embedded in compromised MemTensor npm packages."
        author = "Actioner CTI"
        date = "2026-09-25"
        reference = "https://www.stepsecurity.io/blog/sckit-supply-chain-worm-hits-memtensor-npm-pypi-scopes"

    strings:
        $launcher_func = "launchStageZero" ascii
        $sckit_path = ".sckit/" ascii
        $config64_arg = "--config64" ascii
        $event_env = "SCKIT_EVENT_TEXT" ascii

    condition:
        3 of them
}

rule sckit_pypi_stage0_loader : malware supply_chain
{
    meta:
        description = "Detects the malicious Python stage0 loader used in compromised MemTensor PyPI packages."
        author = "Actioner CTI"
        date = "2026-09-25"
        reference = "https://safedep.io/memtensor-sckit-worm-npm-pypi/"

    strings:
        $stage0_import = "_stage0" ascii
        $trigger_func = "trigger()" ascii
        $sckit_dir = ".sckit" ascii
        $ci_delivery = "_initial_ci_delivery" ascii
        $pypi_bridge = "_pypi_bridge" ascii

    condition:
        3 of them
}

rule sckit_implant_hashes : malware supply_chain
{
    meta:
        description = "Detects known sckit implant binaries by file hash."
        author = "Actioner CTI"
        date = "2026-09-25"
        reference = "https://www.stepsecurity.io/blog/sckit-supply-chain-worm-hits-memtensor-npm-pypi-scopes"

    condition:
        hash.sha256(0, filesize) == "381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18" or
        hash.sha256(0, filesize) == "e077c387b223811064b7bbc5a55a0182fca9bf50894f949ff284d4be87d44b26" or
        hash.sha256(0, filesize) == "65faf8ccbcf5b34eb4f72c71bf82815fa9c1e2f947b9c898491540e866132c31" or
        hash.sha256(0, filesize) == "f8ccdd1da7dff1aef16377a2842bc7acf7c516e32122dd6e42dc4a4e57653fce" or
        hash.sha256(0, filesize) == "56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be" or
        hash.sha256(0, filesize) == "d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26" or
        hash.sha256(0, filesize) == "c1b0998347b489582bae7b7f4930f9831d9ef4b6bc150cfd488ee1a43272dd36" or
        hash.sha256(0, filesize) == "8f647f17a1934679c4095e21bee2b9bd83e28476603758bc91408a0c8443e3b4" or
        hash.sha256(0, filesize) == "9de0d5b0ca184f71f630be5781d134998883a02d5d7bc65aeb9559d8f9efb364" or
        hash.sha256(0, filesize) == "5405e330507602e803f7dd6f2a9d4555aec8558ab222b51413594a962da6888a" or
        hash.sha256(0, filesize) == "16de381deb978744535b10f68fe15165251374b86eef18ffc2c47f61ea673047" or
        hash.sha256(0, filesize) == "f7c4014e284f3d56c452b8b222a287c54f73fc4a40a7e022e765ac8376362947"
}
