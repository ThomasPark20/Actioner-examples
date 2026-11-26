rule Malware_NuGet_WeapF_Recon_Payload
{
    meta:
        description = "Detects the WeapF reconnaissance payload from the malicious NuGet package campaign. Reports host information to Telegram and uses AES-GCM encrypted config from GitHub."
        author = "Actioner"
        date = "2026-11-26"
        reference = "https://socket.dev/blog/malicious-nuget-packages-fake-job-assessments"
        hash = "1bc553ee2324f67c86cf8d9057da242e8ab363c59e452f5a69a1275909c20a97"
        severity = "high"

    strings:
        $pdb = "WeapF" ascii wide
        $pdb2 = "Payload.pdb" ascii wide
        $tg = "api.telegram.org/bot" ascii wide
        $aes_key = "K9vT2mQ7xL4pR8sW1cF6zH3nD5aB0yEa" ascii
        $ip_check = "api.ipify.org" ascii wide
        $generate204 = "generate_204" ascii wide
        $winrse = "winrse.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($pdb and $tg) or
            ($aes_key) or
            ($pdb and $ip_check) or
            ($winrse and $tg) or
            ($pdb2 and 2 of ($tg, $ip_check, $generate204))
        )
}
