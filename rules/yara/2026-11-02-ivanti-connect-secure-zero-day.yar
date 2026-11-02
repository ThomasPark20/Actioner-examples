rule APT_UNC5221_PHASEJAM_Dropper
{
    meta:
        description = "Detects PHASEJAM dropper script used by UNC5221 to deploy web shells on compromised Ivanti Connect Secure appliances after CVE-2025-0282 exploitation"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        severity = "critical"

    strings:
        $s1 = "AccessAllow()" ascii
        $s2 = "/jam/getComponent.cgi" ascii
        $s3 = "sub AccessAllow()" ascii
        $s4 = "cp -f /home/bin/remotedebug" ascii
        $s5 = "pkill cgi-server" ascii
        $s6 = "/home/webserver/htdocs/dana-na" ascii
        $s7 = "remotedebug.bak" ascii
        $s8 = "/auth/restAuth.cgi" ascii
        $s9 = "MIME::Base64" ascii
        $s10 = "HTTP_CODE" ascii

    condition:
        filesize < 20KB and
        8 of ($s*)
}

rule APT_UNC5221_SPAWNANT_Installer
{
    meta:
        description = "Detects SPAWNANT installer (libupgrade.so) used by UNC5221 for persistent access on Ivanti Connect Secure via LD_PRELOAD hijacking of dspkginstall"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        hash = "61bb586dc4e047ab081ef6ca65684e48"
        severity = "critical"

    strings:
        $s1 = "dspkginstall" ascii
        $s2 = "vsnprintf" ascii
        $s3 = "bom_files" ascii
        $s4 = "do-install" ascii
        $s5 = "ld.so.preload" ascii
        $s6 = "LD_PRELOAD" ascii
        $s7 = "scanner.py" ascii

    condition:
        uint32(0) == 0x464C457F and
        5 of ($s*)
}

rule APT_UNC5221_DRYHOOK_Credential_Stealer
{
    meta:
        description = "Detects DRYHOOK credential stealer that patches DSAuth.pm on Ivanti Connect Secure to capture user credentials in RC4-encrypted format"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        hash = "d18e5425ecd9608ecb992606b974e15d"
        severity = "critical"

    strings:
        $s1 = "/home/perl/DSAuth.pm" ascii
        $s2 = "replace_content" ascii
        $s3 = "setPrompt =" ascii
        $s4 = "runSignin = *DSAuthc::RealmSignin_runSignin" ascii
        $s5 = "/bin/mount -o remount,rw /" ascii
        $s6 = "cmdmmap.kuwMW" ascii
        $s7 = "runSigninEBSL" ascii
        $s8 = "pkill cgi-server" ascii
        $s9 = "RC4" ascii

    condition:
        filesize < 20KB and
        8 of ($s*)
}

rule APT_UNC5221_SPAWNSNAIL_SSH_Backdoor
{
    meta:
        description = "Detects SPAWNSNAIL SSH backdoor (libsshd.so) injected into dsmdm and dslogserver on Ivanti Connect Secure appliances"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        hash = "e7d24813535f74187db31d4114f607a1"
        severity = "critical"

    strings:
        $s1 = "PRIVATE KEY-----" ascii
        $s2 = "id_ed25519" ascii
        $s3 = "id_rsa" ascii
        $s4 = "selinux" ascii nocase
        $s5 = "libssh" ascii
        $s6 = "dsmdm" ascii
        $s7 = "dslogserver" ascii

    condition:
        uint32(0) == 0x464C457F and
        $s1 and
        ($s2 or $s3) and
        2 of ($s4, $s5, $s6, $s7)
}

rule APT_UNC5221_SPAWNMOLE_Tunneler
{
    meta:
        description = "Detects SPAWNMOLE tunneler (libsocks5.so) that hooks accept() in the Ivanti web process to tunnel attacker traffic through the appliance"
        author = "Actioner"
        date = "2026-11-02"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day"
        hash = "a638fd203ddb540d0484d8e00490df06"
        severity = "critical"

    strings:
        $s1 = "/proc/self/exe" ascii
        $s2 = "/proc/%d/maps" ascii
        $s3 = "libsocks5" ascii
        $s4 = "accept" ascii
        $elf_hdr = { 7F 45 4C 46 }

    condition:
        $elf_hdr at 0 and
        all of ($s*)
}
