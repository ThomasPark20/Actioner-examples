rule Clop_Windchill_Custom_WebShell_Aug2026
{
    meta:
        description = "Detects the Clop custom JSP web shell deployed against PTC Windchill servers in the August 2026 mass-extortion campaign. The rule targets application-specific strings (WTKeyStoreUtil, WTConnection, MethodContext, ieStructProperties, Flst1) and the X-windchill-req command header that distinguish this implant from generic JSP web shells. Hashes in meta are reference-only (not used in condition); detection relies on string matching. High confidence requires 4+ Windchill API strings or 3+ with the command header."
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://reliaquest.com/blog/clop-returns-with-custom-implant-in-mass-extortion-campaign"
        hash1 = "321e1fb01eb3462b48ff6ccdef132acc1182e3f7456548439f0d4ead12fd98bf"
        hash2 = "55a1eb4c2d3da04376df39d7ba832569c6af1a37a0cf2b95f754ac898023a30c"
        severity = "high"
        tlp = "clear"

    strings:
        $jsp_tag = "<%@" ascii
        $jsp_page = "<%@ page" ascii nocase

        // Windchill-specific internal API references
        $wt_keystore = "WTKeyStoreUtil" ascii
        $wt_connection = "WTConnection" ascii
        $wt_method = "MethodContext" ascii
        $wt_decrypt = "decryptProperty" ascii

        // Credential decryption configuration
        $cred_file = "ieStructProperties" ascii

        // Vault enumeration
        $vault_class = "Flst1" ascii
        $vault_output = "flst.txt" ascii

        // Command dispatch header
        $cmd_header = "X-windchill-req" ascii

        // GZIP response compression
        $gzip_val = "GZIPOutputStream" ascii

    condition:
        filesize < 100KB and
        ($jsp_tag or $jsp_page) and
        (
            // High confidence: 4+ Windchill-specific strings
            (4 of ($wt_keystore, $wt_connection, $wt_method, $wt_decrypt, $cred_file)) or
            // High confidence: 3+ Windchill-specific strings with command header
            ($cmd_header and 3 of ($wt_keystore, $wt_connection, $wt_method, $wt_decrypt, $cred_file)) or
            // Medium confidence: command header + vault enumeration
            ($cmd_header and ($vault_class or $vault_output)) or
            // Medium confidence: command header + credential decryption
            ($cmd_header and ($wt_keystore or $wt_decrypt or $cred_file)) or
            // Medium confidence: command header + GZIP compression in JSP
            ($cmd_header and $gzip_val)
        )
}
