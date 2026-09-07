rule Malware_RedShell_Linux_Implant
{
    meta:
        description = "Detects RedShell Linux implant (RedC2 4.0) via characteristic strings from the trojanized npm supply chain campaign"
        author = "Actioner"
        date = "2026-08-28"
        reference = "https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant"
        hash = "4537B1189CE419F1A595CF47216C03F80E9170CE80DAD8D9227A1E52F9CB3466"
        severity = "critical"

    strings:
        $persist1 = "svc-update.service" ascii
        $persist2 = "system-updater.desktop" ascii
        $persist3 = ".config/.rsvc" ascii

        $tmp1 = "/tmp/.sc_" ascii
        $tmp2 = "/tmp/.elf_" ascii
        $tmp3 = "/tmp/.dl_" ascii
        $tmp4 = "/tmp/.ft_" ascii
        $tmp5 = "/tmp/.sk_" ascii
        $tmp6 = "/tmp/.cr_" ascii

        $cmd1 = "/socks start" ascii
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "memfd_create" ascii

        $c2_ip = "217.60.77.63" ascii

        $net1 = "litterbox.catbox.moe" ascii
        $net2 = "api.ipify.org" ascii

    condition:
        uint32(0) == 0x464C457F and
        filesize < 10MB and
        (
            ($c2_ip and 2 of ($persist*)) or
            (3 of ($tmp*) and 1 of ($cmd*)) or
            ($c2_ip and $cmd3 and 1 of ($tmp*)) or
            ($c2_ip and 1 of ($net*) and 1 of ($persist*))
        )
}
