rule MemTensor_sckit_Go_Implant
{
    meta:
        description = "Detects the sckit Go-based credential stealer implant delivered via compromised MemTensor npm/PyPI packages"
        author = "Actioner"
        date = "2026-09-29"
        reference = "https://safedep.io/memtensor-sckit-worm-npm-pypi/"
        hash_linux_amd64 = "381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18"
        hash_linux_arm64 = "e077c387b223811064b7bbc5a55a0182fca9bf50894f949ff284d4be87d44b26"
        hash_darwin_amd64 = "65faf8ccbcf5b34eb4f72c71bf82815fa9c1e2f947b9c898491540e866132c31"
        hash_darwin_arm64 = "f8ccdd1da7dff1aef16377a2842bc7acf7c516e32122dd6e42dc4a4e57653fce"
        hash_windows_amd64 = "56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be"
        hash_windows_arm64 = "d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26"

    strings:
        // Go module path — unique to this implant
        $go_module = "supplychain.local/campaign/cmd/implant" ascii

        // Internal Go package paths
        $pkg_agent = "internal/agent" ascii
        $pkg_wire = "internal/wire" ascii
        $pkg_presentation = "internal/presentation" ascii

        // C2 domain
        $c2_domain = "skyleen.fr" ascii

        // C2 subdomains (npm variant)
        $c2_npm1 = "8a8acaf167b3.skyleen.fr" ascii
        $c2_npm2 = "0b48fafd6fbe.skyleen.fr" ascii
        $c2_npm3 = "266297c6df27.skyleen.fr" ascii

        // C2 subdomains (PyPI variant)
        $c2_pypi1 = "c747d139e7e9.skyleen.fr" ascii
        $c2_pypi2 = "73376a079d87.skyleen.fr" ascii
        $c2_pypi3 = "d4f77a3a8cb0.skyleen.fr" ascii

        // CI token capture endpoint
        $c2_ci = "10729e014d0e.skyleen.fr" ascii

        // Command-line pattern
        $cmdline_stage0 = "stage0" ascii
        $cmdline_config64 = "--config64" ascii

        // Credential file targets
        $cred1 = ".npmrc" ascii
        $cred2 = ".pypirc" ascii
        $cred3 = ".vault-token" ascii
        $cred4 = ".git-credentials" ascii
        $cred5 = "id_ecdsa" ascii
        $cred6 = "id_ed25519" ascii
        $cred7 = "access_tokens.json" ascii

        // Environment variable targets
        $env1 = "NPM_TOKEN" ascii
        $env2 = "PYPI_API_TOKEN" ascii
        $env3 = "NODE_AUTH_TOKEN" ascii
        $env4 = "SCKIT_EVENT_TEXT" ascii

        // Staging directory names
        $dir1 = ".openclaw" ascii
        $dir2 = ".memos" ascii

        // Go version indicator
        $go_ver = "go1.27" ascii

        // C2 URL paths
        $path_config = "/config" ascii
        $path_status = "/status" ascii
        $path_batch = "/batch" ascii

    condition:
        (
            // Primary: Go module path is unique to this implant
            $go_module
        ) or
        (
            // Secondary: C2 domain with supporting indicators
            $c2_domain and
            (
                any of ($c2_npm*) or any of ($c2_pypi*) or $c2_ci
            )
        ) or
        (
            // Tertiary: combination of behavioral indicators in a Go binary
            uint32(0) == 0x464c457f and  // ELF magic
            $go_ver and
            2 of ($pkg_*) and
            $c2_domain and
            ($cmdline_stage0 or $cmdline_config64)
        ) or
        (
            // Windows PE variant
            uint16(0) == 0x5a4d and  // MZ magic
            $go_ver and
            2 of ($pkg_*) and
            $c2_domain and
            ($cmdline_stage0 or $cmdline_config64)
        ) or
        (
            // Mach-O variant
            (uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcefaedfe or uint32(0) == 0xcffaedfe) and
            $go_ver and
            2 of ($pkg_*) and
            $c2_domain and
            ($cmdline_stage0 or $cmdline_config64)
        ) or
        (
            // Credential harvesting with C2 and staging dirs
            $c2_domain and
            any of ($dir*) and
            3 of ($cred*) and
            any of ($env*)
        ) or
        (
            // C2 paths with domain and env vars
            $c2_domain and
            2 of ($path_*) and
            any of ($env*)
        )
}

rule MemTensor_sckit_NPM_Payload
{
    meta:
        description = "Detects the malicious JavaScript loader (lib/sckit.js) in compromised MemTensor npm packages"
        author = "Actioner"
        date = "2026-09-29"
        reference = "https://semgrep.dev/blog/2026/the-ai-ecosystem-has-worms-now-inside-the-memtensor-compromise/"
        hash_021 = "995a208944176c437a023f4a5c11baad2eb77a91847893c82e5866eaabedb810"
        hash_023 = "6caf89b059e9b6c82bb4ac4727816d516753c4d26833434dea0ecda44a346eb3"
        hash_025 = "a6870826cd7c7ec8d32af227252efcdcdca03ac956d4702cdc2157ca82641673"

    strings:
        $file_sckit = "lib/sckit.js" ascii
        $file_stage0 = "_stage0" ascii
        $c2_domain = "skyleen.fr" ascii
        $env_event = "SCKIT_EVENT_TEXT" ascii
        $openclaw = ".openclaw" ascii
        $memos_cache = ".memos/.cache/runtime" ascii
        $publish_bridge = "sckit-publish-bridge" ascii
        $ci_marker1 = "SCKit credential receipt acknowledged" ascii
        $ci_marker2 = "SCKIT_CI_RESULT_V2" ascii
        $ci_marker3 = "SCKIT_CI_OBSERVATION_V2" ascii

    condition:
        filesize < 5MB and
        (
            ( $c2_domain and ($file_sckit or $file_stage0) ) or
            ( $env_event and any of ($ci_marker*) ) or
            ( $publish_bridge and $c2_domain ) or
            ( $openclaw and $memos_cache and $c2_domain ) or
            ( 2 of ($ci_marker*) and $c2_domain )
        )
}

rule MemTensor_sckit_PyPI_Payload
{
    meta:
        description = "Detects the malicious Python components in compromised MemTensor PyPI MemoryOS package"
        author = "Actioner"
        date = "2026-09-29"
        reference = "https://safedep.io/memtensor-sckit-worm-npm-pypi/"
        hash_wheel = "39ee644406829a4b630b31759c20478bc22d576d6a59b253ed86f72c360aa5ef"
        hash_targz = "92b46d18fc553c494eda714f204459edb74c205bf53b18a9092bcf02c7a6c5be"

    strings:
        $stage0 = "_stage0" ascii
        $log_py = "memos/log.py" ascii
        $mem_cube = "memos/configs/mem_cube.py" ascii
        $c2_domain = "skyleen.fr" ascii
        $pypi_bridge = "_pypi_bridge.sh" ascii
        $ci_delivery = "_initial_ci_delivery.py" ascii
        $poetry_build = "sckit_poetry_build.py" ascii
        $env_event = "SCKIT_EVENT_TEXT" ascii
        $ci_commit = "chore: allow native PyPI upload" ascii

    condition:
        filesize < 10MB and
        (
            ( $c2_domain and ($stage0 or $log_py or $mem_cube) ) or
            ( $pypi_bridge and $c2_domain ) or
            ( $ci_delivery and $c2_domain ) or
            ( $poetry_build and $c2_domain ) or
            ( $ci_commit and ($pypi_bridge or $ci_delivery) ) or
            ( $env_event and ($stage0 or $pypi_bridge) )
        )
}
