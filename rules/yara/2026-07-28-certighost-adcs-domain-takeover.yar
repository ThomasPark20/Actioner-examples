rule Exploit_CVE_2026_54121_Certighost_Tool
{
    meta:
        description = "Detects the Certighost PoC exploit tool (certighost.py) for CVE-2026-54121 targeting AD CS chase enrollment"
        author = "Actioner"
        date = "2026-07-28"
        reference = "https://github.com/aniqfakhrul/CVE-2026-54121"
        severity = "critical"

    strings:
        $class1 = "NLOracle" ascii
        $class2 = "LSASrv" ascii
        $class3 = "RogueLDAP" ascii
        $class4 = "CertServerRequest" ascii
        $class5 = "DirtyDH" ascii

        $func1 = "pkinit_and_hash" ascii
        $func2 = "request_cert" ascii
        $func3 = "build_pkinit_asreq" ascii
        $func4 = "sign_authpack" ascii
        $func5 = "create_computer_samr" ascii
        $func6 = "run_lsa" ascii

        $oid1 = "1.3.6.1.5.2.3.1" ascii
        $oid2 = "91ae6020-9e3c-11cf-8d7c-00aa00c091be" ascii

        $str1 = "certighost" ascii nocase
        $str2 = "EDITF_ENABLECHASECLIENTDC" ascii
        $str3 = "ms-DS-MachineAccountQuota" ascii

    condition:
        filesize < 500KB and
        (
            3 of ($class*) or
            (2 of ($func*) and 1 of ($oid*)) or
            ($str1 and 2 of ($class*, $func*, $oid*)) or
            all of ($str*)
        )
}
