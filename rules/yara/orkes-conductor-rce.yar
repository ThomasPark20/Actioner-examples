rule CVE_2026_58138_Conductor_RCE_Payload
{
    meta:
        description = "Detects exploit payloads for CVE-2026-58138 Orkes Conductor unauthenticated RCE via GraalVM evaluator abuse"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-58138"
        reference2 = "https://opentaint.org/blog/conductor-rce-cve-2026-58138/"
        severity = "critical"
        hash = "n/a"

    strings:
        $api1 = "/api/workflow" ascii wide
        $api2 = "/api/metadata/workflow" ascii wide

        $task1 = "INLINE" ascii wide
        $task2 = "LAMBDA" ascii wide

        $eval1 = "QUERY_EVALUATOR_TYPE" ascii wide
        $eval2 = "QUERY_EXPRESSION_PARAMETER" ascii wide
        $eval3 = "javascript" ascii wide

        $reflect1 = "getClass" ascii wide
        $reflect2 = "forName" ascii wide
        $reflect3 = "java.lang.Runtime" ascii wide
        $reflect4 = "getRuntime" ascii wide
        $reflect5 = "ProcessBuilder" ascii wide
        $reflect6 = "Runtime.getRuntime" ascii wide

        $cmd1 = "sh -c" ascii wide
        $cmd2 = "/bin/sh" ascii wide
        $cmd3 = "/bin/bash" ascii wide

    condition:
        any of ($api*) and
        any of ($task*) and
        any of ($reflect*) and
        (any of ($eval*) or any of ($cmd*))
}

rule CVE_2026_58138_Conductor_PoC_Script
{
    meta:
        description = "Detects known PoC exploit scripts for CVE-2026-58138 Orkes Conductor RCE"
        author = "Actioner"
        date = "2026-09-20"
        reference = "https://github.com/0xgh057r3c0n/CVE-2026-58138"
        severity = "critical"

    strings:
        $cve = "CVE-2026-58138" ascii wide
        $api = "/api/workflow" ascii wide
        $graalvm1 = "HostAccess.ALL" ascii wide
        $graalvm2 = "allowAllAccess" ascii wide
        $conductor = "conductor" ascii wide nocase

        $reflect1 = "getRuntime" ascii wide
        $reflect2 = "java.lang.Runtime" ascii wide
        $reflect3 = "ProcessBuilder" ascii wide

    condition:
        $cve and $api and any of ($reflect*) and $conductor and any of ($graalvm*)
}
