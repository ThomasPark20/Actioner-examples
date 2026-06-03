rule Malware_Sicoob_Sdk_NuGet_CredTheft
{
    meta:
        description = "Detects the malicious Sicoob.Sdk NuGet DLL that exfiltrates PFX certificates and banking credentials to a hardcoded Sentry DSN"
        author = "Actioner"
        date = "2026-06-03"
        reference = "https://socket.dev/blog/malicious-nuget-package-impersonates-sicoob-sdk"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $dsn      = "d565e3f03d0b1a7c8935d7ff94237316" ascii wide
        $host     = "o4511335034847232.ingest.de.sentry.io" ascii wide
        $proj     = "4511337546317904" ascii wide
        $cls      = "SicoobClient" ascii wide
        $api1     = "ReadAllBytes" ascii wide
        $api2     = "ToBase64String" ascii wide
        $sentry1  = "SentrySdk" ascii wide
        $sentry2  = "CaptureMessage" ascii wide

    condition:
        ($dsn or $host or $proj) and
        $cls and
        2 of ($api1, $api2, $sentry1, $sentry2)
}
