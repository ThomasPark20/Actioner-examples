rule Malware_HollowGraph_Cavern_DLL
{
    meta:
        description = "Detects HollowGraph malware DLL via characteristic strings from the Cavern framework C2 component that abuses Microsoft 365 calendar events"
        author = "Actioner"
        date = "2026-07-21"
        reference = "https://www.group-ib.com/blog/hollowgraph-microsoft-365/"
        severity = "high"

    strings:
        $cfg = "logAzure.txt" ascii wide
        $api1 = "calendarView" ascii wide
        $api2 = "/calendar/events" ascii wide
        $subj1 = "Event ID: " ascii wide
        $subj2 = "Boss" ascii wide
        $attach = "File1.txt" ascii wide
        $delim1 = "_;;_" ascii wide
        $delim2 = "_,_" ascii wide
        $debug = "MzU=" ascii wide
        $dns = "cloudlanecdn" ascii wide

    condition:
        filesize < 10MB and
        $cfg and
        (2 of ($api*,$subj*,$attach) or
         2 of ($delim*,$debug) or
         ($dns and 1 of ($api*)))
}
