rule Exploit_Ivanti_Sentry_CVE_2026_10520_Payload
{
    meta:
        description = "Detects exploit payloads or tools targeting Ivanti Sentry CVE-2026-10520 pre-auth OS command injection via the handleMessage endpoint"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://labs.watchtowr.com/more-evidence-that-words-dont-mean-what-we-thought-they-meant-ivanti-sentry-pre-auth-os-command-injection-cve-2026-10520/"
        severity = "critical"

    strings:
        $endpoint = "/mics/api/v2/sentry/mics-config/handleMessage" ascii wide
        $payload1 = "execute system /configuration/system/commandexec" ascii wide
        $payload2 = "<commandexec><index>" ascii wide
        $payload3 = "<reqandres>" ascii wide
        $response = "Message handled successfully" ascii wide

    condition:
        filesize < 1MB and
        $endpoint and
        (2 of ($payload*) or ($payload1 and $response))
}
