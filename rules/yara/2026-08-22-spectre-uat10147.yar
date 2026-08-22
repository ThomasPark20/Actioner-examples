rule UAT10147_SPECTRE_Windows_Campaign_Artifacts
{
    meta:
        description = "Detects UAT-10147 campaign artifacts including SPECTRE backdoor C2 indicators and attacker-compiled tooling PDB paths"
        author = "Actioner"
        date = "2026-08-22"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"

    strings:
        // Attacker-compiled EfsPotato privilege escalation PDB paths
        $pdb1 = "Desktop\\AI\\EfsPotatoCpp\\x64\\Release\\EfsPotato.pdb" ascii
        $pdb2 = "Desktop\\AI\\EfsPotatoCPP\\x64\\Debug\\EfsPotato.pdb" ascii

        // SPECTRE service installer PDB path
        $pdb3 = "svchost\\x64\\Release\\service.pdb" ascii

        // SPECTRE C2 endpoint strings
        $c2a = "/api/v1/register" ascii
        $c2b = "/api/v1/output" ascii

        // SPECTRE named pipe for privilege escalation
        $pipe = "\\\\.\\pipe\\spectre_" ascii

        // SPECTRE NTFS ADS C2 configuration path
        $ads = "drivers\\etc\\hosts:cache" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            any of ($pdb1, $pdb2) or
            ($pdb3 and 1 of ($c2*, $pipe, $ads)) or
            ($pipe and ($c2a or $c2b)) or
            ($ads and ($c2a or $c2b))
        )
}

rule UAT10147_Specter_Linux_Rootkit
{
    meta:
        description = "Detects the Specter Linux kernel rootkit module deployed by UAT-10147 via distinctive hooked syscall function names used for process hiding and network connection concealment. May match educational rootkit projects that reuse identical hooked function naming."
        author = "Actioner"
        date = "2026-08-22"
        reference = "https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/"
        severity = "critical"

    strings:
        $hook1 = "hooked_tcp6_seq_show" ascii
        $hook2 = "hooked_tcp4_seq_show" ascii
        $hook3 = "hooked_tkill" ascii
        $hook4 = "hooked_tgkill" ascii
        $hook5 = "hooked_kill" ascii
        $hook6 = "hooked_getdents64" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 5MB and
        3 of ($hook*)
}
