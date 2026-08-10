rule Malware_DEVPOPPER_Joyfill_Bundle
{
    meta:
        description = "Detects malicious @joyfill npm bundle with DEV#POPPER loader strings from the July 2026 supply chain compromise"
        author = "Actioner"
        date = "2026-08-01"
        reference = "https://socket.dev/blog/joyfill-npm-beta-releases-compromised"
        severity = "critical"

    strings:
        $marker1 = "9-0135-3" ascii
        $marker2 = "global[\"!\"]" ascii
        $xor1 = "2[gWfGj;<:-93Z^C" ascii
        $xor2 = "m6:tTh^D)cBz?NM]" ascii
        $inject1 = "/*C250617A*/" ascii
        $inject2 = "/*C260511A*/" ascii
        $inject3 = "/*RS260605*/" ascii
        $global_stash = "global.r = require" ascii
        $throttle = "global._p_t" ascii

    condition:
        filesize < 5MB and (
            ($marker1 and ($xor1 or $xor2)) or
            ($marker2 and $throttle) or
            (3 of ($inject*)) or
            ($global_stash and $throttle and $marker1)
        )
}
