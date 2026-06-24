rule Vuln_NGINX_CVE_2026_42530_CVE_2026_42055 : vulnerability
{
    meta:
        description = "Detects NGINX binaries in the version range affected by CVE-2026-42530 (HTTP/3 UAF, 1.31.0-1.31.1) and CVE-2026-42055 (HTTP/2 HPACK overflow, 1.13.10-1.31.1). Covers the union of both CVEs' affected version ranges."
        author = "Actioner"
        date = "2026-06-22"
        reference = "https://nginx.org/en/security_advisories.html"
        severity = "critical"

    strings:
        $nginx_banner = "nginx/" ascii

        $vuln_v3_10 = "nginx/1.31.0" ascii
        $vuln_v3_11 = "nginx/1.31.1" ascii
        $vuln_v3_00 = "nginx/1.30.0" ascii
        $vuln_v3_01 = "nginx/1.30.1" ascii
        $vuln_v3_02 = "nginx/1.30.2" ascii

        $vuln_v29 = "nginx/1.29." ascii
        $vuln_v28 = "nginx/1.28." ascii
        $vuln_v27 = "nginx/1.27." ascii
        $vuln_v26 = "nginx/1.26." ascii
        $vuln_v25 = "nginx/1.25." ascii
        $vuln_v24 = "nginx/1.24." ascii
        $vuln_v23 = "nginx/1.23." ascii
        $vuln_v22 = "nginx/1.22." ascii
        $vuln_v21 = "nginx/1.21." ascii
        $vuln_v20 = "nginx/1.20." ascii
        $vuln_v19 = "nginx/1.19." ascii
        $vuln_v18 = "nginx/1.18." ascii
        $vuln_v17 = "nginx/1.17." ascii
        $vuln_v16 = "nginx/1.16." ascii
        $vuln_v15 = "nginx/1.15." ascii
        $vuln_v14 = "nginx/1.14." ascii

        $vuln_v13 = "nginx/1.13." ascii
        $vuln_v13_10 = "nginx/1.13.10" ascii
        $vuln_v13_11 = "nginx/1.13.11" ascii

        $http2_module = "ngx_http_v2_module" ascii
        $http3_module = "ngx_http_v3_module" ascii
        $proxy_v2 = "ngx_http_proxy_v2" ascii
        $grpc_module = "ngx_http_grpc_module" ascii

    condition:
        $nginx_banner and
        (
            1 of ($vuln_v3*) or
            1 of ($vuln_v2*) or
            1 of ($vuln_v1*) or
            1 of ($vuln_v13*)
        ) and
        (
            $http2_module or $http3_module or $proxy_v2 or $grpc_module
        )
}
