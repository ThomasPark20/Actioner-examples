rule FastJson_CVE_2026_16723_Exploit_Payload
{
    meta:
        description = "Detects FastJson CVE-2026-16723 exploitation payloads containing @type with jar: URI schemes"
        author = "Actioner"
        date = "2026-07-29"
        reference = "https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/"
        reference2 = "https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation"
        cve = "CVE-2026-16723"
        severity = "critical"
        tlp = "white"

    strings:
        $type_field = "@type" ascii wide
        $jar_http = "jar:http" ascii wide nocase
        $jar_file = "jar:file" ascii wide nocase
        $json_type = "@JSONType" ascii wide
        $parse_obj = "parseObject" ascii wide
        $fastjson = "fastjson" ascii wide nocase

    condition:
        $type_field and ($jar_http or $jar_file) and (($json_type or $parse_obj or $fastjson) or filesize < 10KB)
}

rule FastJson_CVE_2026_16723_Exploit_Tool
{
    meta:
        description = "Detects tools or scripts designed to exploit FastJson CVE-2026-16723"
        author = "Actioner"
        date = "2026-07-29"
        reference = "https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/"
        cve = "CVE-2026-16723"
        severity = "high"
        tlp = "white"

    strings:
        $cve = "CVE-2026-16723" ascii wide nocase
        $fastjson_rce = "fastjson" ascii wide nocase
        $jar_http = "jar:http" ascii wide nocase
        $jar_file = "jar:file" ascii wide nocase
        $type = "@type" ascii wide
        $safe_mode = "safeMode" ascii wide
        $autotype = "AutoType" ascii wide
        $spring_boot = "spring-boot" ascii wide nocase
        $fat_jar = "fat-jar" ascii wide nocase

    condition:
        ($cve and any of ($fastjson_rce, $jar_http, $jar_file, $type, $safe_mode, $autotype, $spring_boot, $fat_jar)) or ($fastjson_rce and $type and ($jar_http or $jar_file) and any of ($safe_mode, $autotype, $spring_boot, $fat_jar))
}
