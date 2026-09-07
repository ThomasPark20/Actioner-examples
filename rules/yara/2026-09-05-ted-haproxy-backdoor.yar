rule DPRK_Ted_HAProxy_Backdoor : backdoor apt
{
    meta:
        description = "Detects the Ted backdoor compiled into trojanized HAProxy binaries, targeting South Korean organizations. Keys on distinctive ted_plugin function names, C2 config paths, build identifiers, and the substitution cipher alphabet unique to this implant."
        author = "Actioner"
        date = "2026-09-05"
        reference = "https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/"
        hash = "94630b96f628c96a6bff7904b40ffc9ad67c86f8a4ff6080c3b524831c93f402"
        hash = "72e70936f0dbe459142a1d867617c35f8d0cce5d18c6a49e1090a2a5adc8e558"
        hash = "a8bfab4de81a1acb04aacdf757346946b0f5e30f0c9f402004016d0e425119c7"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // Ted plugin function names (debug symbols)
        $fn1 = "ted_load_filter_config" ascii
        $fn2 = "ted_chn_analyze_for_htx" ascii
        $fn3 = "ted_http_headers_for_htx" ascii
        $fn4 = "ted_http_payload" ascii
        $fn5 = "ted_pipe_master_thread" ascii
        $fn6 = "ted_pipe_worker_thread" ascii
        $fn7 = "ted_flt_register_ops2" ascii
        $fn8 = "ted_task_for_response" ascii
        $fn9 = "ted_reload_filter_config" ascii
        $fn10 = "ted_load_ip_set" ascii
        $fn11 = "ted_save_capture_log2" ascii

        // C2 config file paths
        $path1 = "haproxy-1000.cache" ascii
        $path2 = "haproxy-1001.cache" ascii
        $path3 = "haproxy-1002.cache" ascii

        // Build ID and version string
        $build = "24112201" ascii
        $ver = "2.8.12-0fdb194" ascii

        // C2 authentication token
        $api_token = "ecd427ea8330a4ff73618483e00b9b41" ascii

        // C2 trigger URI
        $trigger_uri = "favorite_list_2x_m500_ico.jpg" ascii

        // Nginx-reuse indicator (code heritage)
        $ngx1 = "ngx_decode" ascii
        $ngx2 = "ngx_decrypt_script" ascii

        // Named pipe pattern
        $pipe = "_w.pipe" ascii

        // Substitution cipher alphabet fragment (unique to ted)
        $cipher = "E1x0X3f2R5w4g7u6D968kAeCdBPEpDhGJF4IiHHKzJvMtLl" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 25MB and
        (
            (3 of ($fn*)) or
            (2 of ($path*) and ($ver or $build)) or
            ($api_token) or
            ($trigger_uri and 1 of ($fn*)) or
            ($cipher) or
            (1 of ($ngx*) and $pipe and 1 of ($path*))
        )
}

rule DPRK_CurlRAT_Trojanized_Binary : backdoor apt
{
    meta:
        description = "Detects CurlRAT variants masquerading as legitimate Linux daemons (crond, sshd, agetty, atd, polkitd) used alongside the Ted HAProxy backdoor in DPRK-attributed operations."
        author = "Actioner"
        date = "2026-09-05"
        reference = "https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/"
        hash = "5db1b6d52faf60b4f32d6fd0c7c938e4d05d29a14c32ded4a9668357c08b6a91"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // CurlRAT function naming convention (atd_ prefix on CentOS variants)
        $atd1 = "atd_reverse_try_root" ascii
        $atd2 = "atd_reverse_create_conn" ascii
        $atd3 = "atd_http_request" ascii
        $atd4 = "atd_download_to_file" ascii
        $atd5 = "atd_get_system_info" ascii
        $atd6 = "atd_create_id" ascii
        $atd7 = "atd_encrypt_url" ascii
        $atd8 = "atd_decrypt_url" ascii
        $atd9 = "atd_check_haproxy" ascii
        $atd10 = "atd_run_shell" ascii

        // Victim ID generation seed string
        $id_seed = "cron_3.0pl1-137ubuntu3" ascii

        // C2 POST body format
        $post_fmt = "name=%s&value=%s&type=%d" ascii

        // CurlRAT config paths
        $cfg1 = "/var/lib/snapd/g580" ascii
        $cfg2 = "/var/lib/snapd/g105" ascii

        // Virtualization check marker
        $virt_check = "/usr/lib/libvirtlog.so.0" ascii

        // C2 HTTP header
        $header1 = "User-token" ascii
        $header2 = "api_token" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            (3 of ($atd*)) or
            ($id_seed) or
            ($post_fmt and $virt_check) or
            (2 of ($cfg*) and 1 of ($header*))
        )
}
