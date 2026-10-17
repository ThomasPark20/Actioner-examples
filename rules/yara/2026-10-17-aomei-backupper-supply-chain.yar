rule Malware_CROSSROAD_Downloader
{
    meta:
        description = "Detects CROSSROAD downloader from AOMEI Backupper supply chain attack (UNC7017). Keys on distinctive metadata typo, self-deletion flag, and scheduled task name."
        author = "Actioner"
        date = "2026-10-17"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering"
        hash = "11e576df44e9c9eef72b9f5b699291bcdb200a19130778ec231e5b0987b913ad"
        severity = "high"

    strings:
        $meta_typo = "AOMEI Update Compent" ascii wide
        $nitrod = "--nitrod" ascii
        $nitrodp = "NITRODP" ascii
        $nitrodt = "NITRODT" ascii
        $task = "RadminComponentRuntime" ascii wide
        $runtimechk = "--runtimechk" ascii
        $mutex = "{F9E6E3C0-E11A-4F85-9944-AF4AD6E05883}" ascii wide
        $wtfbbq = ":wtfbbq" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($meta_typo and 2 of ($nitrod, $nitrodp, $nitrodt, $task, $runtimechk)) or
            ($mutex and $task) or
            ($wtfbbq and $nitrod and $task)
        )
}

rule Malware_SHINYROAD_Backdoor
{
    meta:
        description = "Detects SHINYROAD backdoor components from AOMEI Backupper supply chain attack (UNC7017). Keys on PocketPy bootstrap script name, handshake string, and traffic chaffing config."
        author = "Actioner"
        date = "2026-10-17"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering"
        hash = "8fbaa74b27dc1e89abfc694e834378746f0ad37a688098c5f8f511410157c8b8"
        severity = "high"

    strings:
        $handshake = "mct3-handshake-v1" ascii
        $bootstrap = "bootstrap_tcp_slim_v2_call_min.py" ascii
        $jam1 = "JAM_BURST_PACKETS_MIN" ascii
        $jam2 = "JAM_MIN_MS" ascii
        $jam3 = "JAM_MAX_BYTES" ascii
        $pyio1 = "_pyio_compat" ascii
        $pyio2 = "_pyio_struct" ascii
        $shm = "963d3c60-d406-4ad6-aa1e-dc8e45061ccf" ascii

    condition:
        filesize < 10MB and
        (
            ($handshake and $bootstrap) or
            ($handshake and 2 of ($jam*)) or
            (2 of ($pyio*) and $shm) or
            (3 of them)
        )
}

rule Malware_ADAPTAGENT_Loader
{
    meta:
        description = "Detects ADAPTAGENT (Adaptix C2) loader masquerading as Nitro PDF software, used as follow-on tooling in the AOMEI Backupper supply chain attack. Note: the ($s2 and ($s3 or $s4)) branch detects the Adaptix C2 framework generally, not only this campaign's deployment."
        author = "Actioner"
        date = "2026-10-17"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering"
        hash = "14b31918075e6130b9123158743db0a81e2d7bfcf6d39731ee7d9200a98cd591"
        severity = "high"

    strings:
        $s1 = "NitroPromotion.exe" ascii wide
        $s2 = "Adaptix Crash Analyzer v1.0" ascii wide
        $s3 = "13ConnectorHTTP" ascii
        $s4 = "9Connector" ascii
        $mutex = "{8d00c640-48d8-4440-a8e1-660fd37f572a}" ascii wide
        $pipe = "\\\\.\\pipe\\%08lx" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($s2 and ($s3 or $s4)) or
            ($mutex and $s1) or
            (3 of them)
        )
}
