import "pe"

rule Exploit_CVE_2026_20337_ZIP_Catalogue_Overflow
{
    meta:
        description = "Detects malformed ZIP archives with central directory anomalies that may trigger CVE-2026-20337 heap overflow in ClamAV ZIP catalogue capacity tracking"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26"
        severity = "low"

    strings:
        // ZIP local file header signature
        $lfh = { 50 4B 03 04 }
        // ZIP central directory file header signature
        $cdfh = { 50 4B 01 02 }
        // ZIP end of central directory record
        $eocd = { 50 4B 05 06 }

    condition:
        // Must be a ZIP file
        $lfh at 0 and
        $eocd and
        filesize < 50MB and
        // Anomaly: central directory headers significantly outnumber local file headers
        // (indicates potential catalogue capacity manipulation for overflow)
        #cdfh > #lfh * 3 and #cdfh > 100
}

rule Exploit_CVE_2026_20339_PESpin_Anomaly
{
    meta:
        description = "Detects PESpin-packed PE files with anomalous section sizes that may trigger CVE-2026-20339 integer overflow in ClamAV PESpin unpacker"
        author = "Actioner"
        date = "2026-08-11"
        reference = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-WuuvVd26"
        severity = "high"

    strings:
        // PESpin signature markers in PE overlay/section
        $pespin1 = "PESpin" ascii nocase
        $pespin2 = { 50 45 53 70 69 6E }
        // Common PESpin stub entry patterns
        $stub1 = { EB 01 ?? 60 E8 00 00 00 00 }
        $stub2 = { 9C 60 E8 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (1 of ($pespin*) or 1 of ($stub*)) and
        // Anomalous section virtual size (very large, potential integer overflow trigger)
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].virtual_size > 0x7FFFFFFF or
            pe.sections[i].raw_data_size > filesize
        )
}
