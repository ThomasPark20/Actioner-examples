rule Turla_CerealLoader_DotNet_NativeEntryPoint
{
    meta:
        description = "Detects CerealLoader .NET assemblies with native entry points"
        author = "CTI Analysis (DRAFT)"
        date = "2026-11-10"
        reference = "https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/"
        hash1 = "4A3C263977417FB6977B0E598C9E3BC5924F390C"
        hash2 = "7742C6B0AAF114335CEF7EBAB11290CB18A0B8B3"
        hash3 = "5B94FE76EC4FEB0B5CB6EA3BCA4C48D2FE22597B"
        severity = "medium"
    strings:
        $mz = "MZ"
        $dotnet_sig = { 42 53 4A 42 }
        $confuserex1 = "ConfuserEx" ascii wide
        $confuserex2 = "Confuser" ascii wide
        $method1 = "RaiseOnRoutedMessage" ascii wide
        $method2 = "GetManifestResourceNames" ascii wide
        $method3 = "GetManifestResourceStream" ascii wide
        $binfmt = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter" ascii wide
        $asmload = "System.Reflection.Assembly" ascii wide
    condition:
        $mz at 0 and $dotnet_sig and
        (
            ($confuserex1 or $confuserex2) and
            ($method2 or $method3) and $binfmt
        ) or
        (
            $mz at 0 and $dotnet_sig and
            $method1 and ($asmload or $binfmt)
        )
}

rule Turla_CerealNeuron_URI_Prefixes
{
    meta:
        description = "Detects CerealNeuron passive backdoor by URI listener prefixes"
        author = "CTI Analysis (DRAFT)"
        date = "2026-11-10"
        reference = "https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/"
        severity = "high"
    strings:
        $uri1 = "/owa/sdds/" ascii wide nocase
        $uri2 = "/autodiscover/microsoft.exchange.proxyservice/" ascii wide nocase
        $uri3 = "/autodiscover/integrated/api/" ascii wide nocase
        $uri4 = "/autodiscover/proxyservice/" ascii wide nocase
        $uri5 = "/microsoft-server-activesync/integrated/api/" ascii wide nocase
        $httplistener = "System.Net.HttpListener" ascii wide
        $rsa = "RSAParameters" ascii wide
        $mz = "MZ"
        $dotnet_sig = { 42 53 4A 42 }
    condition:
        $mz at 0 and $dotnet_sig and $httplistener and $rsa and
        2 of ($uri1, $uri2, $uri3, $uri4, $uri5)
}

rule Turla_CerealBox_Exchange_Transport_Hijack
{
    meta:
        description = "Detects CerealBox email collection via Exchange transport hijack"
        author = "CTI Analysis (DRAFT)"
        date = "2026-11-10"
        reference = "https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/"
        severity = "medium"
    strings:
        $mz = "MZ"
        $dotnet_sig = { 42 53 4A 42 }
        $transport1 = "Microsoft.Exchange.Transport" ascii wide
        $transport2 = "EdgeTransport" ascii wide
        $transport3 = "RoutingAgentFactory" ascii wide
        $transport4 = "Microsoft.Exchange.Data.Transport" ascii wide
        $ext1 = ".doc" ascii wide
        $ext2 = ".docx" ascii wide
        $ext3 = ".pdf" ascii wide
        $mime = "MimeDocument" ascii wide
        $resolve = "AssemblyResolve" ascii wide
        $expath = "ExchangeInstallPath" ascii wide
    condition:
        $mz at 0 and $dotnet_sig and
        2 of ($transport1, $transport2, $transport3, $transport4) and
        2 of ($ext1, $ext2, $ext3) and
        ($mime or $resolve or $expath)
}

rule Turla_Cereal_IOC_ConfigKey
{
    meta:
        description = "Detects Cereal toolset by shared configuration key"
        author = "CTI Analysis (DRAFT)"
        date = "2026-11-10"
        reference = "https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/"
        severity = "high"
    strings:
        $config_key = "B38C96AE6643D2AB5C0BFE823D9C9017" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and $config_key
}
