rule Exploit_CVE_2026_53435_Jenkins_ConfigXML_Deserialization
{
    meta:
        description = "Detects potentially malicious Jenkins config.xml files containing XStream deserialization payloads targeting CVE-2026-53435"
        author = "Actioner"
        date = "2026-06-15"
        reference = "https://www.jenkins.io/security/advisory/2026-06-10/#SECURITY-3707"
        severity = "high"

    strings:
        $xml_header = "<?xml" ascii nocase
        $deser1 = "java.lang.ProcessBuilder" ascii
        $deser2 = "java.lang.Runtime" ascii
        $deser3 = "javax.imageio" ascii
        $deser4 = "groovy.lang.GroovyShell" ascii
        $deser5 = "groovy.lang.GroovyClassLoader" ascii
        $deser6 = "java.beans.EventHandler" ascii
        $deser7 = "com.sun.org.apache.xalan" ascii
        $deser8 = "javax.script.ScriptEngineManager" ascii
        $jenkins1 = "<project>" ascii nocase
        $jenkins2 = "<flow-definition" ascii nocase
        $jenkins3 = "hudson." ascii

    condition:
        $xml_header and
        1 of ($jenkins*) and
        1 of ($deser*)
}
