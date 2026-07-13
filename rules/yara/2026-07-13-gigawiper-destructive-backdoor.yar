rule Malware_GigaWiper_Backdoor_Strings
{
    meta:
        description = "Detects GigaWiper Golang-based destructive backdoor via characteristic strings from the malware's command dispatch, wiper, and encryption routines"
        author = "Actioner"
        date = "2026-07-13"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"
        hash = "633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001"
        hash2 = "ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913"
        severity = "critical"

    strings:
        $s1 = "Partitions removed successfully" ascii
        $s2 = "kharbvnmhkjbkjb" ascii
        $s3 = ".candy" ascii
        $s4 = "Task created. Original process exiting" ascii
        $s5 = "Running from Task Scheduler" ascii
        $s6 = "BigBangExtortMain" ascii
        $s7 = "cmd.Task" ascii
        $s8 = "cmd.Result" ascii
        $s9 = "createProcess" ascii
        $s10 = "resumeProcess" ascii
        $s11 = "suspendProcess" ascii
        $s12 = "killProcess" ascii
        $go = "Go build" ascii

    condition:
        filesize < 30MB and
        $go and
        4 of ($s*)
}
