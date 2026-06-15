rule Exploit_CVE_2026_53435_Jenkins_ConfigXML_Deserialization
{
    meta:
        description = "Detects malicious Jenkins config.xml files with XStream deserialization gadgets targeting CVE-2026-53435. Deploy as correlation data — requires environmental tuning."
        author = "Actioner"
        date = "2026-06-15"
        reference = "https://www.jenkins.io/security/advisory/2026-06-10/#SECURITY-3707"
        severity = "medium"

    strings:
        $xml_header = "<?xml" ascii nocase
        $deser1 = "java.lang.ProcessBuilder" ascii
        $deser2 = "groovy.lang.GroovyShell" ascii
        $deser3 = "groovy.lang.GroovyClassLoader" ascii
        $deser4 = "java.beans.EventHandler" ascii
        $deser5 = "com.sun.org.apache.xalan" ascii
        $jenkins1 = "<project>" ascii nocase
        $jenkins2 = "<flow-definition" ascii nocase

    condition:
        $xml_header and
        1 of ($jenkins*) and
        2 of ($deser*)
}
