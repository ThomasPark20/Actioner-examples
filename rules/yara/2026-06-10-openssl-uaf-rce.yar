rule Exploit_CVE_2026_45447_PKCS7_Empty_DigestAlgorithms
{
    meta:
        description = "Detects PKCS#7 SignedData with empty digestAlgorithms SET, the trigger for CVE-2026-45447 use-after-free in PKCS7_verify()"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://securityonline.info/openssl-security-patches-rce/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // PKCS#7 SignedData OID: 1.2.840.113549.1.7.2
        $pkcs7_signed_data_oid = { 06 09 2A 86 48 86 F7 0D 01 07 02 }

        // Empty SET (digestAlgorithms = SET OF with zero elements)
        // In DER: SET tag (0x31) + length 0 (0x00)
        $empty_set = { 31 00 }

    condition:
        $pkcs7_signed_data_oid and
        $empty_set and
        // Empty SET must appear within 256 bytes after the OID (within the SignedData structure)
        for any i in (1..#empty_set) : (
            for any j in (1..#pkcs7_signed_data_oid) : (
                @empty_set[i] > @pkcs7_signed_data_oid[j] and
                @empty_set[i] - @pkcs7_signed_data_oid[j] < 256
            )
        ) and
        filesize < 10MB
}
