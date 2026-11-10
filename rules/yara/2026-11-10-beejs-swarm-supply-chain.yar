rule beejs_malicious_loader_generate_version_cjs {
    meta:
        description = "Detects the malicious loader injected into bee-js 13.3.0 scripts/generate-version.cjs"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f"
        severity = "high"
    strings:
        $url = "api.frameworkmetrics.xyz" ascii wide
        $path1 = "/v1/analytics" ascii wide
        $path2 = "/v1/electron" ascii wide
        $header = "X-Ethersphere" ascii wide
        $exec = "new Function('require', 'console', 'process'" ascii wide
        $log = "[FrameworkMetrics] analytics" ascii wide
    condition:
        $url or ($exec and ($header or $path1 or $path2)) or $log
}

rule beejs_malicious_package_tgz {
    meta:
        description = "Detects the malicious bee-js 13.3.0 npm tarball by package name, version, and injected postinstall hook"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "d01fdf241aa9e0a1ba6ebc19f8f667af1bf652745021c5050126cb7036f7ce58"
        severity = "high"
    strings:
        $pkg = "@ethersphere/bee-js" ascii
        $ver = "13.3.0" ascii
        $postinstall = "node scripts/generate-version.cjs" ascii
    condition:
        all of them
}

rule evjawbreaker_staging_directory {
    meta:
        description = "Detects scripts associated with the evjawbreaker Go backdoor staging directory (.solidity)"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        severity = "high"
    strings:
        $dir1 = ".solidity/" ascii wide
        $runner_py = ".run.py" ascii wide
        $runner_cjs = ".run.cjs" ascii wide
        $service = "solidity-langsupport-runner" ascii wide
        $launchagent = "com.solidity.langsupport.runner" ascii wide
    condition:
        $dir1 and ($runner_py or $runner_cjs or $service or $launchagent)
}

rule evjawbreaker_go_backdoor {
    meta:
        description = "Detects the evjawbreaker Go remote shell backdoor binary by embedded strings"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        severity = "high"
    strings:
        $mod = "evjawbreaker" ascii wide
        $contract = "0xf8a900Db50b3331be6B768bA460BB59f3E40C344" ascii wide nocase
        $selector = "0x02d91518" ascii wide
        $ankr = "rpc.ankr.com" ascii wide
        $cfeth = "cloudflare-eth.com" ascii wide
    condition:
        $mod or ($contract and $selector) or ($contract and ($ankr or $cfeth))
}

rule screenconnect_malicious_instance {
    meta:
        description = "Detects the specific ScreenConnect instance ID used in the bee-js supply chain attack Windows payload"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash_msi = "7527e86d70e7c9493db4356f1c3775380431b310000f2602c1e993cf435d01da"
        severity = "high"
    strings:
        $instance_id = "5cbe79c9c25524df" ascii wide nocase
        $relay = "185.232.84.169" ascii wide
    condition:
        $instance_id and $relay
}

rule invoke_ps1_swarm_attack {
    meta:
        description = "Detects the obfuscated PowerShell loader used in the Windows stage of the bee-js supply chain attack"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "37d14bff30762ca701e9c1f8bc6c57c065bb20ae3a2208cb7411a6530610f08e"
        severity = "high"
    strings:
        $stuffed = ".stuffed-" ascii wide
        $defender_excl = "Add-MpPreference" ascii wide
        $cor_profiler = "COR_PROFILER" ascii wide
        $mmc = "mmc.exe" ascii wide
    condition:
        $stuffed and ($defender_excl or ($cor_profiler and $mmc))
}

rule swarm_desktop_malicious_index_js {
    meta:
        description = "Detects the malicious index.js injected into Swarm Desktop 0.56.2 app.asar"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "f81315968e679b48f6bdff1c9b928bb223230d07f44d7948412c2250c2a14deb"
        severity = "high"
    strings:
        $url = "api.frameworkmetrics.xyz" ascii wide
        $path = "/v1/electron" ascii wide
        $header = "X-Ethersphere" ascii wide
    condition:
        all of them
}

rule swarm_wallet_exfiltration_endpoint {
    meta:
        description = "Detects references to the wallet exfiltration endpoint used in the bee-js supply chain attack"
        author = "CTI Analyst (Actioner)"
        date = "2026-11-10"
        reference = "https://socket.dev/blog/bee-js-compromise"
        severity = "high"
    strings:
        $exfil = "/v1/swarm/report" ascii wide
        $domain = "frameworkmetrics" ascii wide
    condition:
        all of them
}
