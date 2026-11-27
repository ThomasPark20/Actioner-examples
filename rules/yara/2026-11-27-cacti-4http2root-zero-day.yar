// Cacti 4HTTP2ROOT Zero-Day — YARA Detection Rules
// Source: Actioner CTI report 2026-11-27-cacti-4http2root-zero-day
// Post-review: 1 rule kept (Proof_File at high confidence)
// Dropped: Webshell_Indicator (matched legitimate Cacti source files)

rule Cacti_4HTTP2ROOT_Proof_File
{
    meta:
        description = "Detects the proof-of-concept output file created by the Cacti 4HTTP2ROOT exploit chain (cache/4http2root-proof.txt)"
        author = "Actioner"
        date = "2026-11-27"
        reference = "https://github.com/ekomsSavior/Sad-Girls-0day-Club/tree/main/4http2shell"
        hash = "n/a"

    strings:
        $proof_filename = "4http2root-proof" ascii wide
        $poc_marker1 = "4http2root" ascii wide nocase
        $poc_marker2 = "4http2shell" ascii wide nocase
        $poc_repo = "Sad-Girls-0day-Club" ascii wide

    condition:
        filesize < 1MB and ($proof_filename or $poc_repo or ($poc_marker1 and $poc_marker2))
}
