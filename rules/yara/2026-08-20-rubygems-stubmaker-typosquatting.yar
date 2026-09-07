rule Malware_StubMaker_RubyGems_Typosquat
{
    meta:
        description = "Detects the 16 malicious RubyGems packages from the StubMaker typosquatting campaign by matching gem metadata name fields and distinctive extconf.rb stub code patterns."
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
        severity = "critical"

    strings:
        // Malicious gem names in gemspec/metadata
        $gem01 = "\"ubnuler\"" ascii
        $gem02 = "\"ubnlder\"" ascii
        $gem03 = "\"ri18nr\"" ascii
        $gem04 = "\"reaker\"" ascii
        $gem05 = "\"rakier\"" ascii
        $gem06 = "\"orakw\"" ascii
        $gem07 = "\"joxn\"" ascii
        $gem08 = "\"ise18n\"" ascii
        $gem09 = "\"ioe18n\"" ascii
        $gem10 = "\"ie18u\"" ascii
        $gem11 = "\"iai8n\"" ascii
        $gem12 = "\"i1l8n\"" ascii
        $gem13 = "\"i18om\"" ascii
        $gem14 = "\"activesupmport\"" ascii
        $gem15 = "\"brumdler\"" ascii
        $gem16 = "\"brundlef\"" ascii

        // StubMaker extconf.rb patterns - empty Makefile targets
        $stub1 = "all:" ascii
        $stub2 = "install:" ascii
        $stub3 = "clean:" ascii
        $stub4 = "create_makefile" ascii

        // Payload fetch indicators
        $fetch1 = "bebraz1" ascii
        $fetch2 = "wincfg" ascii
        $fetch3 = "abe_payload" ascii

    condition:
        filesize < 25MB and
        (
            any of ($gem*) or
            ($fetch1 and $fetch2) or
            ($fetch1 and $fetch3) or
            (all of ($stub*) and any of ($fetch*))
        )
}

rule Malware_StubMaker_Wincfg_Stealer
{
    meta:
        description = "Detects the StubMaker Go-based wincfg stealer binary by matching distinctive strings related to browser credential theft, Gofile exfiltration, and the C2 domain."
        author = "Actioner"
        date = "2026-08-20"
        reference = "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
        severity = "critical"

    strings:
        // C2 and exfil infrastructure
        $c2 = "dresslee.com" ascii wide
        $gofile = "gofile.io" ascii wide
        $ipify = "api.ipify.org" ascii wide

        // Stealer component names
        $payload_name = "wincfg" ascii wide
        $dll_name = "abe_payload.dll" ascii wide

        // Browser data paths targeted
        $chrome = "\\Google\\Chrome\\User Data\\" ascii wide
        $edge = "\\Microsoft\\Edge\\User Data\\" ascii wide
        $brave = "\\BraveSoftware\\Brave-Browser\\User Data\\" ascii wide
        $opera = "\\Opera Software\\Opera Stable\\" ascii wide
        $vivaldi = "\\Vivaldi\\User Data\\" ascii wide
        $yandex = "\\Yandex\\YandexBrowser\\User Data\\" ascii wide

        // Credential file targets
        $login = "Login Data" ascii wide
        $cookies = "Cookies" ascii wide
        $localstate = "Local State" ascii wide

        // Telegram data
        $telegram = "Telegram Desktop" ascii wide

    condition:
        filesize < 25MB and
        (
            ($c2 and ($gofile or $ipify)) or
            ($payload_name and $dll_name) or
            ($c2 and 3 of ($chrome, $edge, $brave, $opera, $vivaldi, $yandex)) or
            ($c2 and $login and $cookies and $localstate and $telegram)
        )
}
