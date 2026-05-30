rule npm_depconf_moika_stager
{
    meta:
        description = "npm dependency-confusion moika.tech postinstall stager / dropped init files"
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/"
        mitre = "T1195.003,T1027,T1059.007,T1071.001"
    strings:
        $secret = "l95HdDaz3kQx1Zsg3WxH6HvKANf51RY1" ascii
        $c2     = "oob.moika.tech" ascii nocase
        $ep1    = "/payload/win" ascii
        $ep2    = "/payload/mac" ascii
        $ep3    = "/payload/linux" ascii
        $hdr    = "X-Secret" ascii
        $r1     = "process.versions.node" ascii
        $r2     = "os.platform" ascii
    condition:
        $secret or $c2 or
        ( $hdr and 1 of ($ep*) and 1 of ($r*) )
}
