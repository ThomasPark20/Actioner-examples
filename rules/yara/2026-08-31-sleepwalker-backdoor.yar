/*
  YARA Rule: SLEEPWALKER Backdoor - File-Level Detection
  Status: DRAFT / PoC
  Author: CTI Draft (automated)
  Date: 2026-08-31
  Reference: https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
*/

import "hash"
import "pe"

rule SLEEPWALKER_Backdoor_Hash
{
    meta:
        description = "Detects SLEEPWALKER backdoor by known SHA-256 hash"
        author = "CTI Draft (automated)"
        date = "2026-08-31"
        reference = "https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html"
        severity = "critical"
        hash = "d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60"
        tlp = "TLP:CLEAR"

    condition:
        hash.sha256(0, filesize) == "d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60"
}

rule SLEEPWALKER_Backdoor_DLL_Masquerade
{
    meta:
        description = "Detects unsigned DLL masquerading as dpapi.dll with SLEEPWALKER size and export characteristics"
        author = "CTI Draft (automated)"
        date = "2026-08-31"
        reference = "https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html"
        severity = "high"
        tlp = "TLP:CLEAR"

    strings:
        // PE MZ header
        $mz = "MZ"

        // Internal name or original filename referencing dpapi
        $int_name = "dpapi.dll" ascii nocase
        $orig_name = "dpapi" ascii nocase

        // Strings suggestive of the bytecode interpreter or AES-CCM usage
        $s_aes = "AES" ascii wide
        $s_ccm = "CCM" ascii wide

    condition:
        $mz at 0 and
        filesize == 59904 and
        pe.is_dll() and
        pe.number_of_exports >= 7 and
        (
            $int_name or
            ($orig_name and 2 of ($s_*))
        )
}
