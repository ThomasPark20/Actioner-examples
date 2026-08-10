/*
 * CVE-2026-66066 KindaRails2Shell - YARA Rules
 * Rails Active Storage arbitrary file read / RCE via libvips matload
 * Author: Actioner | Date: 2026-08-02
 */

rule Exploit_CVE_2026_66066_Crafted_MAT_HDF5
{
    meta:
        description = "Detects MATLAB 5.0 / HDF5 files matching the byte pattern used in CVE-2026-66066 exploitation against Rails Active Storage. Note: legitimate MATLAB v7.3 files share this structure; pair with upload context for triage."
        author = "Actioner"
        date = "2026-08-02"
        reference = "https://github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm"
        severity = "high"

    strings:
        $matlab_header = "MATLAB 5.0" ascii
        $hdf5_magic = { 89 48 44 46 0D 0A 1A 0A }

    condition:
        $matlab_header at 0 and
        $hdf5_magic in (128..1024) and
        filesize < 1MB
}

rule Exploit_CVE_2026_66066_POC_Marker
{
    meta:
        description = "Detects the specific PoC payload marker string used in CVE-2026-66066 exploit tools targeting Rails Active Storage"
        author = "Actioner"
        date = "2026-08-02"
        reference = "https://github.com/Zer0SumGam3/CVE-2026-66066-POC"
        severity = "critical"

    strings:
        $marker = "RAILS_GHSA_OAST_PAYLOAD_V1" ascii

    condition:
        $marker and filesize < 1MB
}
