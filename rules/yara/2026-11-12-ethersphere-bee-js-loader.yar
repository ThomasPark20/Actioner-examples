rule Supply_Chain_BeeJS_Malicious_Loader
{
    meta:
        description = "Detects the malicious generate-version.cjs loader from bee-js 13.3.0 supply chain compromise"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://socket.dev/blog/bee-js-compromise"
        hash = "ee2f762e9ed3fd89f106e0b80c2e923bf1aed9a280277d3d998a5902c4d9ec0f"
        severity = "critical"

    strings:
        $func_sink = "new Function('require', 'console', 'process', body)" ascii
        $c2_path1 = "/v1/analytics" ascii
        $c2_path2 = "/v1/electron" ascii
        $header = "X-Ethersphere" ascii
        $domain = "api.frameworkmetrics.xyz" ascii
        $log_decoy = "[FrameworkMetrics] analytics" ascii

    condition:
        filesize < 50KB and
        $domain and
        (2 of ($func_sink, $header, $log_decoy, $c2_path1, $c2_path2))
}
