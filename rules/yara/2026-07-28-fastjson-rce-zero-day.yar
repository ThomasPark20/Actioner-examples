rule Exploit_CVE_2026_16723_FastJson_RCE_Payload
{
    meta:
        description = "Detects FastJson CVE-2026-16723 exploit payloads containing @type with jar: URL patterns used to achieve RCE in Spring Boot fat-JAR deployments"
        author = "Actioner"
        date = "2026-07-28"
        reference = "https://www.bleepingcomputer.com/news/security/hackers-target-us-firms-in-fastjson-rce-zero-day-attacks/"
        severity = "critical"

    strings:
        $type = "\"@type\"" ascii wide nocase
        $jar_http = "jar:http" ascii wide nocase
        $jar_file = "jar:file" ascii wide nocase
        $jsontype = "@JSONType" ascii wide
        $parse1 = "JSON.parse" ascii
        $parse2 = "JSON.parseObject" ascii
        $getresource = "getResourceAsStream" ascii

    condition:
        filesize < 10MB and
        $type and
        ($jar_http or $jar_file) and
        any of ($jsontype, $parse1, $parse2, $getresource)
}

rule Exploit_CVE_2026_16723_FastJson_Minimal_Payload
{
    meta:
        description = "Detects minimal FastJson CVE-2026-16723 exploit payload signatures in HTTP traffic captures or files containing @type combined with nested jar: URL patterns"
        author = "Actioner"
        date = "2026-07-28"
        reference = "https://threatbook.io/blog/fastjson-rce-1.2.83-active-exploitation-detected-detection-mitigation"
        severity = "high"

    strings:
        $sig1 = "@type\":\"jar:file:" ascii wide nocase
        $sig2 = "@type\":\"jar:http:" ascii wide nocase

    condition:
        filesize < 10MB and
        any of them
}
