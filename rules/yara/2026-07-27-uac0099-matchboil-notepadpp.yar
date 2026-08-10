rule UAC0099_MATCHBOIL_V2_Campaign_Artifacts
{
    meta:
        description = "Detects UAC-0099 MATCHBOIL.V2, LUNCHPOKE, or BURNYBEAR PE components based on campaign-specific strings including scheduled task paths, C2 infrastructure, and loader artifacts"
        author = "Actioner"
        date = "2026-07-27"
        reference = "https://thehackernews.com/2026/07/fake-notepad-plugin-delivers.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        $task_path = "\\W1n3r-U09oTy-Ap5\\Updates" ascii wide
        $args = "setup nodisplay" ascii wide
        $c2_domain = "geostat.lat" ascii wide
        $c2_path = "/articles/images/forest.jpg" ascii wide
        $loader = "RemoteLibUpdater" ascii wide
        $payload = "InitTest.dll" ascii wide
        $rar = "updater.rar" ascii wide
        $bg_schtasks = "\\Wallpapers\\Background.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        2 of them
}
