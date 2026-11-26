rule APT_ArmCastle_BONESAW_vCenter_Exploit
{
    meta:
        description = "Detects BONESAW Go ELF exploitation utility used by Armory Castle (UNC5221) to exploit CVE-2026-123890 against VMware vCenter"
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        hash = ""
        severity = "critical"
        tlp = "TLP:CLEAR"

    strings:
        // SRP-6a prime constant used in exploitation
        $srp_prime = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" ascii

        // vmdirdbcp RPC interface UUID
        $uuid_dbcp = "72c780fe-af6b-42ba-9b02-f61f4ccc98ed" ascii

        // rpc_srp_verifier RPC interface UUID
        $uuid_srp = "c7e94609-6ab0-4767-8e92-b6485bff1649" ascii

        // Build path leaked in Go binary
        $build_path = "VulnScan/Vcenter/go_teamcheck" ascii

        // Internal tool name
        $tool_name = "vcenter-db-teamcheck-go" ascii

        // Output directory pattern
        $output_dir = "extracted_tenant_signer_" ascii

        // Output file pattern
        $output_mdb = "anon_%s_data.mdb" ascii

        // Tenant credential extraction
        $tenant_cred = "tenantcredential" ascii

    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        filesize < 50MB and
        $srp_prime and
        (
            ($uuid_dbcp and $uuid_srp) or
            ($build_path) or
            ($tool_name and $output_dir) or
            ($output_mdb and $tenant_cred)
        )
}

rule APT_ArmCastle_SAWSNAKE_SAML_Forge
{
    meta:
        description = "Detects SAWSNAKE Go ELF SAML token forgery utility used by Armory Castle (UNC5221) for Golden SAML attacks against vCenter"
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        hash = ""
        severity = "critical"
        tlp = "TLP:CLEAR"

    strings:
        // Output file names characteristic of SAWSNAKE
        $out_idp = "idp_key.pem" ascii
        $out_cert = "trusted_cert_2.pem" ascii
        $out_domain = "domain.txt" ascii

        // SAML SSO endpoint used for session cookie generation
        $saml_sso = "/ui/saml/websso/sso" ascii

        // Port of vcenter_saml_login.py reference
        $saml_login = "vcenter_saml_login" ascii

        // SAML assertion forging strings
        $saml_assert = "SAMLResponse" ascii

        // vCenter data.mdb extraction for IdP keys
        $data_mdb = "data.mdb" ascii

    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        filesize < 30MB and
        (
            ($out_idp and $out_cert and $out_domain) or
            ($saml_login and $saml_sso) or
            ($saml_sso and $out_idp and $saml_assert and $data_mdb)
        )
}

rule APT_ArmCastle_BEARBONES_Dropbear_Backdoor
{
    meta:
        description = "Detects BEARBONES modified Dropbear SSH backdoor used by Armory Castle (UNC5221) with hardcoded auth bypass and distinctive banner"
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        hash = ""
        severity = "critical"
        tlp = "TLP:CLEAR"

    strings:
        // Distinctive SSH banner used by BEARBONES
        $banner = "SSH-2.0-pulsesecure_23345" ascii

        // Host key paths in /tmp
        $key_rsa = "/tmp/rsa_host_key" ascii
        $key_ecdsa = "/tmp/ecdsa_host_key" ascii
        $key_dss = "/tmp/dss_host_key" ascii

        // Dropbear internal strings
        $dropbear = "dropbear" ascii nocase

        // Port 33992 as string (alternative listening port)
        $port_alt = "33992" ascii

    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        filesize < 5MB and
        (
            $banner or
            (2 of ($key_rsa, $key_ecdsa, $key_dss) and $dropbear) or
            ($banner and $port_alt)
        )
}

rule APT_ArmCastle_LAZYBONES_Slack_C2
{
    meta:
        description = "Detects LAZYBONES Go ELF backdoor used by Armory Castle (UNC5221) that uses Slack API for C2 with AES-256-CTR encryption"
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        hash = ""
        severity = "critical"
        tlp = "TLP:CLEAR"

    strings:
        // Slack API endpoints used for C2
        $slack_history = "conversations.history" ascii
        $slack_upload = "files.getUploadURLExternal" ascii
        $slack_complete = "files.completeUploadExternal" ascii

        // C2 commands
        $cmd_handler = "cmd" ascii
        $upload_handler = "upload" ascii
        $download_handler = "download" ascii
        $sleep_handler = "sleep" ascii

        // Masquerade path
        $masq_path = "/usr/bin/vmtoolscs" ascii

        // Slack API base
        $slack_api = "slack.com/api/" ascii

    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        filesize < 30MB and
        (
            (2 of ($slack_history, $slack_upload, $slack_complete)) or
            ($slack_api and $masq_path) or
            ($slack_history and $masq_path and 2 of ($cmd_handler, $upload_handler, $download_handler, $sleep_handler))
        )
}

rule APT_ArmCastle_SLIMSAVAGE_Webshell
{
    meta:
        description = "Detects SLIMSAVAGE JSP web shell used by Armory Castle (UNC5221) with hardcoded password authentication and command execution"
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        hash = ""
        severity = "critical"
        tlp = "TLP:CLEAR"

    strings:
        // Hardcoded authentication parameter
        $auth = "pwd=123" ascii

        // ProcessBuilder command execution pattern
        $exec = "ProcessBuilder(\"/bin/sh\",\"-c\"" ascii

        // Alternative ProcessBuilder variants
        $exec2 = "ProcessBuilder" ascii
        $exec3 = "/bin/sh" ascii

        // File name
        $filename = "ActiveSer.jsp" ascii

    condition:
        filesize < 100KB and
        (
            ($auth and $exec) or
            ($auth and $exec2 and $exec3) or
            ($filename and $auth)
        )
}

rule APT_ArmCastle_CAGEMATCH_Webshell
{
    meta:
        description = "Detects CAGEMATCH JSP web shell used by Armory Castle (UNC5221) for multipart file upload to staging directories"
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        hash = ""
        severity = "high"
        tlp = "TLP:CLEAR"

    strings:
        // Multipart upload handling
        $multipart = "multipart" ascii nocase
        $boundary = "boundary" ascii nocase

        // /tmp staging directory
        $tmp_staging = "/tmp/" ascii

        // File upload JSP patterns
        $file_upload = "FileOutputStream" ascii

        // File name indicator
        $filename = "u.jsp" ascii

    condition:
        filesize < 100KB and
        (
            ($filename and $multipart and $tmp_staging) or
            ($multipart and $boundary and $tmp_staging and $file_upload)
        )
}
