rule ACTIONER_Webshell_SLIMSAVAGE_1 {
    meta:
        description = "Detects SLIMSAVAGE JSP web shell used by ARMORY CASTLE in CVE-2026-123890 exploitation"
        author = "Actioner Research (based on GTIG indicators)"
        date = "2026-11-20"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        threat_actor = "ARMORY CASTLE / UNC5221"
        severity = "critical"

    strings:
        $auth = "if(\"123\".equals(request.getParameter(\"pwd\")))" ascii
        $exec = "new ProcessBuilder(\"/bin/sh\",\"-c\",request.getParameter(\"i\"))" ascii
        $stream = "InputStream a = p.getInputStream(), b = p.getErrorStream();" ascii
        $jsp = "<%@" ascii

    condition:
        $jsp and all of ($auth, $exec, $stream)
}

rule ACTIONER_Webshell_CAGEMATCH_1 {
    meta:
        description = "Detects CAGEMATCH JSP upload web shell used by ARMORY CASTLE in CVE-2026-123890 exploitation"
        author = "Actioner Research (based on GTIG indicators)"
        date = "2026-11-20"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        threat_actor = "ARMORY CASTLE / UNC5221"
        severity = "critical"

    strings:
        $boundary = "request.getContentType().split(\"boundary=\")" ascii
        $tmpwrite = "File f=new File(\"/tmp\");f.mkdirs();File fout=new File(f,fname);" ascii
        $jsp = "<%@" ascii

    condition:
        $jsp and ($boundary and $tmpwrite)
}

rule ACTIONER_Utility_BONESAW_1 {
    meta:
        description = "Detects BONESAW Go-based exploit utility targeting CVE-2026-123890 in VMware vCenter"
        author = "Actioner Research (based on GTIG indicators)"
        date = "2026-11-20"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        threat_actor = "ARMORY CASTLE / UNC5221"
        severity = "critical"

    strings:
        $mdb_path = "/storage/db/vmware-vmdir/data.mdb" ascii
        $srp_prime = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" ascii nocase
        $uuid_dbcp = "72c780fe-af6b-42ba-9b02-f61f4ccc98ed" ascii nocase
        $uuid_srp = "c7e94609-6ab0-4767-8e92-b6485bff1649" ascii nocase
        $dev_path = "VulnScan/Vcenter/go_teamcheck" ascii
        $internal_name = "vcenter-db-teamcheck-go" ascii
        $elf = {7F 45 4C 46}

    condition:
        $elf at 0 and $mdb_path and ($srp_prime or $uuid_dbcp or $uuid_srp or $dev_path or $internal_name)
}

rule ACTIONER_Backdoor_BEARBONES_1 {
    meta:
        description = "Detects BEARBONES backdoored Dropbear SSH server used by ARMORY CASTLE"
        author = "Actioner Research (based on GTIG indicators)"
        date = "2026-11-20"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        threat_actor = "ARMORY CASTLE / UNC5221"
        severity = "critical"

    strings:
        $banner = "SSH-2.0-pulsesecure_23345" ascii
        $hostkey_rsa = "/tmp/rsa_host_key" ascii
        $hostkey_ecdsa = "/tmp/ecdsa_host_key" ascii
        $hostkey_dss = "/tmp/dss_host_key" ascii
        $elf = {7F 45 4C 46}

    condition:
        $elf at 0 and $banner and 2 of ($hostkey_rsa, $hostkey_ecdsa, $hostkey_dss)
}

rule ACTIONER_Utility_SAWSNAKE_1 {
    meta:
        description = "Detects SAWSNAKE Go utility for Golden SAML attacks against VMware vCenter, used by ARMORY CASTLE"
        author = "Actioner Research (based on GTIG indicators)"
        date = "2026-11-20"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        threat_actor = "ARMORY CASTLE / UNC5221"
        severity = "critical"

    strings:
        $success = "[+] Successfully obtained Administrator cookies for %s!" ascii
        $saml_url = "https://%s/ui/saml/websso/sso" ascii
        $go_mdb = "saml_login/mdb.go" ascii
        $go_saml = "saml_login/saml.go" ascii
        $go_c14n = "saml_login/c14n.go" ascii
        $elf = {7F 45 4C 46}

    condition:
        $elf at 0 and (2 of ($go_mdb, $go_saml, $go_c14n) or ($success and $saml_url))
}

rule ACTIONER_Backdoor_LAZYBONES_1 {
    meta:
        description = "Detects LAZYBONES Go Slack-C2 backdoor used by ARMORY CASTLE"
        author = "Actioner Research (based on GTIG indicators)"
        date = "2026-11-20"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"
        threat_actor = "ARMORY CASTLE / UNC5221"
        severity = "critical"

    strings:
        $fn1 = "main.AesCtfCrypt_fromconf" ascii
        $fn2 = "main.AesCtfDecrypt_fromconf" ascii
        $fn3 = "main.uploadSlackFile" ascii
        $fn4 = "main.getLastMessage" ascii
        $fn5 = "main.exec_my" ascii
        $slack1 = "files.getUploadURLExternal" ascii
        $slack2 = "files.completeUploadExternal" ascii
        $status1 = "ok,current sleep is:" ascii
        $status2 = "get but not function" ascii
        $status3 = "readfile fail:" ascii
        $elf = {7F 45 4C 46}

    condition:
        $elf at 0 and (3 of ($fn1, $fn2, $fn3, $fn4, $fn5) or (2 of ($slack1, $slack2) and 2 of ($status1, $status2, $status3)))
}
