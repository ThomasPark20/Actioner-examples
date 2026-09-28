rule memtensor_sckit_implant
{
    meta:
        description = "Detects the sckit Go-based credential stealer/implant delivered via compromised MemTensor npm/PyPI packages (supply chain attack, Sep 2026)"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html"
        npm_hash_linux_amd64 = "381ac6dc1715d9298fe81b2a53a11f7b7d78e361ee3a6619ad54f8c4b062cc18"
        npm_hash_linux_arm64 = "e077c387b223811064b7bbc5a55a0182fca9bf50894f949ff284d4be87d44b26"
        npm_hash_darwin_amd64 = "65faf8ccbcf5b34eb4f72c71bf82815fa9c1e2f947b9c898491540e866132c31"
        npm_hash_darwin_arm64 = "f8ccdd1da7dff1aef16377a2842bc7acf7c516e32122dd6e42dc4a4e57653fce"
        npm_hash_windows_amd64 = "56cd3416d2ec2aa7e7cec2a06010cf0b58eb09c0a5486809df52afeaca8f14be"
        npm_hash_windows_arm64 = "d6b3e77c36ee8017c9bf30d1da7218ec0ea843768d313eb8e35845c8a9b38a26"
        pypi_hash_linux_amd64 = "c1b0998347b489582bae7b7f4930f9831d9ef4b6bc150cfd488ee1a43272dd36"
        pypi_hash_linux_arm64 = "8f647f17a1934679c4095e21bee2b9bd83e28476603758bc91408a0c8443e3b4"
        pypi_hash_darwin_amd64 = "9de0d5b0ca184f71f630be5781d134998883a02d5d7bc65aeb9559d8f9efb364"
        pypi_hash_darwin_arm64 = "5405e330507602e803f7dd6f2a9d4555aec8558ab222b51413594a962da6888a"
        pypi_hash_windows_amd64 = "16de381deb978744535b10f68fe15165251374b86eef18ffc2c47f61ea673047"
        pypi_hash_windows_arm64 = "f7c4014e284f3d56c452b8b222a287c54f73dc4a40a7e022e765ac8376362947"

    strings:
        $go_module = "supplychain.local/campaign/cmd/implant" ascii
        $func1 = "readCredentialFile" ascii
        $func2 = "extractJSONCredentials" ascii
        $func3 = "recursivePublish" ascii
        $func4 = "prepareRemoteRepository" ascii
        $config_schema = "sckit.runtime.v1" ascii
        $campaign_id = "cloud-openclaw-semi-nuclear" ascii
        $c2_domain = "skyleen.fr" ascii
        $stage0_arg = "stage0" ascii
        $config64_arg = "--config64" ascii

    condition:
        (
            uint32(0) == 0x464C457F or
            uint16(0) == 0x5A4D or
            uint32(0) == 0xFEEDFACE or
            uint32(0) == 0xFEEDFACF or
            uint32(0) == 0xCEFAEDFE or
            uint32(0) == 0xCFFAEDFE
        )
        and (
            $go_module or
            ($config_schema and $campaign_id) or
            (2 of ($func1, $func2, $func3, $func4)) or
            ($c2_domain and $stage0_arg and $config64_arg)
        )
}

rule memtensor_sckit_npm_loader
{
    meta:
        description = "Detects the sckit JavaScript loader (lib/sckit.js) from compromised @memtensor/memos-cloud-openclaw-plugin npm package"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://socket.dev/blog/memtensor-compromise"
        npm_pkg_hash_0_1_21 = "995a208944176c437a023f4a5c11baad2eb77a91847893c82e5866eaabedb810"
        npm_pkg_hash_0_1_23 = "6caf89b059e9b6c82bb4ac4727816d516753c4d26833434dea0ecda44a346eb3"
        npm_pkg_hash_0_1_25 = "a6870826cd7c7ec8d32af227252efcdcdca03ac956d4702cdc2157ca82641673"

    strings:
        $sckit_path = ".sckit/" ascii
        $stage0 = "stage0" ascii
        $config64 = "--config64" ascii
        $openclaw = "openclaw" ascii
        $spawn = "spawn" ascii
        $devnull = "/dev/null" ascii

    condition:
        filesize < 256KB and
        $sckit_path and $stage0 and $config64 and
        ($openclaw or ($spawn and $devnull))
}

rule memtensor_sckit_python_loader
{
    meta:
        description = "Detects the sckit Python loader from compromised MemoryOS PyPI package"
        author = "Actioner"
        date = "2026-09-28"
        reference = "https://socket.dev/blog/memtensor-compromise"
        pypi_wheel_hash = "39ee644406829a4b630b31759c20478bc22d576d6a59b253ed86f72c360aa5ef"
        pypi_sdist_hash = "92b46d18fc553c494eda714f204459edb74c205bf53b18a9092bcf02c7a6c5be"

    strings:
        $stage0_py = "_stage0.py" ascii
        $sckit_config = "_sckit_config64" ascii
        $pypi_bridge = "_pypi_bridge.sh" ascii
        $ci_delivery = "_initial_ci_delivery.py" ascii
        $sckit_poetry = "sckit_poetry_build" ascii

    condition:
        filesize < 10MB and 3 of them
}
