rule SmartApeSG_Okendo_JS_Injection_Loader
{
    meta:
        description = "Detects the SmartApeSG JavaScript injection loader used in the Okendo Reviews supply chain attack, matching obfuscated localStorage tracking, User-Agent filtering, and XOR fragment patterns"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://www.zscaler.com/blogs/security-research/smartapesg-launches-okendo-reviews-supply-chain-attack"
        severity = "high"

    strings:
        $ls1 = "localStorage['getItem']" ascii
        $ls2 = "localStorage['setItem']" ascii
        $ua = "/Android|iPhone/i" ascii
        $ua2 = "navigator['userAgent']" ascii
        $xor1 = "1f044640" ascii
        $xor2 = "044a1d1f" ascii
        $xor3 = "16005b1e" ascii
        $xor4 = "0019484a" ascii
        $xor5 = "141f5f1f" ascii
        $xor6 = "141c5359" ascii
        $domain1 = "wigetticks.com" ascii
        $domain2 = "wizzleticks.com" ascii
        $path1 = "private-response.php" ascii
        $path2 = "scope-schema.php" ascii

    condition:
        filesize < 5MB and
        (
            (2 of ($ls*) and 1 of ($ua*)) or
            (3 of ($xor*)) or
            (1 of ($domain*) and 1 of ($path*))
        )
}

rule SmartApeSG_HTA_Dropper
{
    meta:
        description = "Detects the SmartApeSG HTA dropper payload used to stage RAT and stealer delivery in ClickFix attack chains"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://isc.sans.edu/diary/32826"
        hash = "212d8007a7ce374d38949cf54d80133bd69338131670282008940f1995d7a720"
        severity = "high"

    strings:
        $hta1 = "<HTA:APPLICATION" ascii nocase
        $hta2 = "<script" ascii nocase
        $url1 = "urotypos.com" ascii
        $url2 = "/cd/temp" ascii
        $url3 = "/ls/production" ascii
        $ps1 = "powershell" ascii nocase
        $ps2 = "Invoke-WebRequest" ascii nocase
        $ps3 = "Start-Process" ascii nocase
        $path1 = "AppData\\Local\\post.hta" ascii
        $path2 = "Public\\Music\\" ascii
        $path3 = "ProgramData\\" ascii

    condition:
        filesize < 200KB and
        (
            (1 of ($hta*) and 1 of ($url*)) or
            ($url1 and 1 of ($ps*)) or
            (1 of ($hta*) and 1 of ($ps*) and 1 of ($path*) and $url1)
        )
}

rule SmartApeSG_FakeBrowserUpdate_JS
{
    meta:
        description = "Detects SmartApeSG fake browser update JavaScript dropper files that deliver NetSupport RAT via social engineering"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://www.esentire.com/blog/smartapesg-delivering-netsupport-rat"
        severity = "high"

    strings:
        $fn = "Update_browser" ascii
        $fn2 = "UpdateInstaller" ascii
        $ns1 = "client32.exe" ascii
        $ns2 = "client32.ini" ascii
        $ns3 = "rtrs.zip" ascii
        $b64 = "FromBase64String" ascii
        $zip = "Expand-Archive" ascii nocase
        $reg = "CurrentVersion\\Run" ascii

    condition:
        filesize < 2MB and
        (
            (1 of ($fn*) and 1 of ($ns*)) or
            (1 of ($ns*) and $b64 and $zip) or
            (1 of ($ns*) and $reg)
        )
}
