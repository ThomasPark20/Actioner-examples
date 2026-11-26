rule Malware_NuGet_SelfSignedCert_MicrosoftSpoof
{
    meta:
        description = "Detects binaries signed with the self-signed certificate spoofing Microsoft Windows Publisher, used across payloads in the malicious NuGet package campaign."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        severity = "high"

    strings:
        $cert_cn = "Microsoft Windows Publisher" ascii wide
        $cert_serial = "505524D1ACD4CAAD4A1C119312B0E1D1" ascii nocase
        $cert_sha1 = "50F2E9C97C3C15AC3C7ABBAD47A272BDFE47ACEF" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        ($cert_serial or $cert_sha1 or ($cert_cn and 2 of them))
}
