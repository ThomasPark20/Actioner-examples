/*
    YARA Rules for CVE-2026-114938 (Java4Shell)
    Detects exploit tools, crash artifacts, and trigger patterns.

    References:
        https://calif.io/java4shell
        https://github.com/alt3kx/CVE-2026-114938
        https://blackpointcyber.com/blog/java4shell-cve-2026-114938-java-base64-decoder-flaw/
*/

rule Java4Shell_Exploit_Tool
{
    meta:
        description = "Detects known Java4Shell (CVE-2026-114938) exploit tools and PoC scripts"
        author = "Actioner Research"
        date = "2026-11-20"
        reference = "https://github.com/alt3kx/CVE-2026-114938"
        cve = "CVE-2026-114938"
        confidence = "high"

    strings:
        $poc_name1 = "CVE-2026-114938" ascii wide
        $poc_name2 = "cve_2026_114938" ascii wide
        $poc_name3 = "java4shell" ascii wide nocase
        $tool_str1 = "Base64TriggerSDE" ascii
        $tool_str2 = "JavaBleed" ascii wide
        $tool_str3 = "UseBASE64Intrinsics" ascii
        $trigger_64a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ascii
        $trigger_128a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ascii

    condition:
        (any of ($poc_name*) and any of ($tool_str*)) or
        (any of ($poc_name*) and any of ($trigger_*)) or
        (2 of ($tool_str*))
}

rule Java4Shell_JVM_Crash_Log
{
    meta:
        description = "Detects JVM crash logs (hs_err_pid) potentially caused by CVE-2026-114938 heap corruption"
        author = "Actioner Research"
        date = "2026-11-20"
        reference = "https://blackpointcyber.com/blog/java4shell-cve-2026-114938-java-base64-decoder-flaw/"
        cve = "CVE-2026-114938"
        confidence = "medium"

    strings:
        $header = "# A fatal error has been detected by the Java Runtime Environment" ascii
        $signal = "SIGSEGV" ascii
        $base64_ref = "java.util.Base64" ascii
        $decoder_ref = "Base64$Decoder" ascii
        $intrinsic = "_base64_decodeBlock" ascii

    condition:
        $header and $signal and
        any of ($base64_ref, $decoder_ref, $intrinsic)
}

rule Java4Shell_Trigger_Pattern
{
    meta:
        description = "Detects the specific trigger pattern for CVE-2026-114938 in network captures or files"
        author = "Actioner Research"
        date = "2026-11-20"
        reference = "https://calif.io/java4shell"
        cve = "CVE-2026-114938"
        confidence = "medium"

    strings:
        // 64 A's followed by = (the standard trigger)
        $trigger_std = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ascii
        // 128 A's followed by = (the JDK 17 variant)
        $trigger_jdk17 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ascii
        // Authorization Basic header context
        $auth_header = "Authorization: Basic" ascii nocase

    condition:
        any of ($trigger_*) and $auth_header
}
