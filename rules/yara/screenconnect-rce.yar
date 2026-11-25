rule Actioner_CVE_2026_84869_Rogue_ScreenConnect_Installer
{
    meta:
        description = "Detects the rogue ScreenConnect MSI installer used in CVE-2026-84869 exploitation (WindowsUpdate.WindowsClient.exe dropped via wclient_*.msi)"
        author = "Actioner"
        date = "2026-11-25"
        reference = "https://www.huntress.com/blog/cve-2026-84869-screenconnect-technician-exploitation"
        hash = "f8871b1561d5c77c297378a7f49c84de52a01ff297395544f0e95d13ef972841"
        severity = "critical"

    strings:
        $msi_name = "wclient_" ascii wide
        $relay_host = "masterdarky.com" ascii wide
        $exe_name = "WindowsUpdate.WindowsClient.exe" ascii wide
        $sc_relay = "relay.screenconnect.com" ascii wide

    condition:
        uint16(0) == 0xCFD0 and
        filesize < 50MB and
        ($relay_host or ($msi_name and $exe_name)) and
        not $sc_relay
}

rule Actioner_CVE_2026_84869_Rogue_SC_Client_PE
{
    meta:
        description = "Detects the rogue ScreenConnect client PE (WindowsUpdate.WindowsClient.exe) connecting to attacker relay on port 8041"
        author = "Actioner"
        date = "2026-11-25"
        reference = "https://www.huntress.com/blog/cve-2026-84869-screenconnect-technician-exploitation"
        hash = "f8871b1561d5c77c297378a7f49c84de52a01ff297395544f0e95d13ef972841"
        severity = "critical"

    strings:
        $relay_host = "masterdarky.com" ascii wide
        $exe_name = "WindowsUpdate.WindowsClient" ascii wide
        $port_str = "8041" ascii
        $pe_mz = { 4D 5A }

    condition:
        $pe_mz at 0 and
        filesize < 50MB and
        $relay_host and
        ($exe_name or $port_str)
}
