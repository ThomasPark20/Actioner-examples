rule APT_Turla_STOCKSTAY_STOCKTRADER_Backdoor
{
    meta:
        description = "Detects STOCKSTAY.STOCKTRADER backdoor component based on known command handler class names"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "0a545dd1b703cddfb3d582c8c70f65f556bbd580bfa836a387121eb837bda61b"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $cmd_1 = "AppDel" ascii
        $cmd_2 = "AppDeleteRegistryValue" ascii
        $cmd_3 = "AppDir" ascii
        $cmd_4 = "AppGet" ascii
        $cmd_5 = "AppMkdir" ascii
        $cmd_6 = "AppPut" ascii
        $cmd_7 = "AppReadRegistryValue" ascii
        $cmd_8 = "AppRegistryKeyExists" ascii
        $cmd_9 = "AppRmdir" ascii
        $cmd_10 = "AppRun" ascii
        $cmd_11 = "AppWriteRegistryValue" ascii
        $cmd_12 = "AppUnpackArchive" ascii
        $cmd_13 = "ArchiveFiles" ascii
        $cmd_14 = "GetFiles" ascii

        $class_1 = "SMEditorPage" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (10 of ($cmd*) or ($class_1 and 5 of ($cmd*)))
}

rule APT_Turla_STOCKSTAY_STOCKMARKET_Orchestrator
{
    meta:
        description = "Detects STOCKSTAY.STOCKMARKET orchestrator component based on protocol message classes and timer methods"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "9164054d0bf0b7c8820da4f742860940998984555e65820e4fa8dd07b6bd67ec"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $proto_1 = "ProtocolMessageConnect" ascii
        $proto_2 = "ProtocolMessageEnd" ascii
        $proto_3 = "ProtocolMessagePing" ascii
        $proto_4 = "ProtocolMessageRequestRecv" ascii
        $proto_5 = "ProtocolMessageRequestSend" ascii
        $proto_6 = "ProtocolMessageTask" ascii
        $proto_7 = "ProtocolMessageTaskSysinfo" ascii

        $tmr_1 = "TMR_AppInit_Tick" ascii
        $tmr_2 = "TMR_Engine_Tick" ascii
        $tmr_3 = "TMR_KeepAlive_Tick" ascii
        $tmr_4 = "TMR_PingNet_Tick" ascii
        $tmr_5 = "TMR_PingSystem_Tick" ascii

        $sql_1 = "CREATE TABLE IF NOT EXISTS News (" wide
        $sql_2 = "CREATE TABLE IF NOT EXISTS Trade (" wide
        $sql_3 = "CREATE TABLE IF NOT EXISTS Market (" wide

        $class_1 = "StockMarketViewPage" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (5 of ($proto*) or (3 of ($tmr*) and 1 of ($sql*)) or ($class_1 and 3 of ($proto*)))
}

rule APT_Turla_STOCKSTAY_STOCKBROKER_Tunneler
{
    meta:
        description = "Detects STOCKSTAY.STOCKBROKER tunneler component based on IPC message handler and WebSocket variable names"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "34fcbe7e90fc87a4f3766469c19a64f24672d7adb99e0198f5ba10d58911368b"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $s1 = "_CorExeMain" ascii
        $s2 = "ProtocolMessageStatusConnection" ascii
        $s3 = "ProtocolMessageResult" ascii
        $s4 = "ProtocolMessageEnd" ascii
        $s5 = "OnGetDataFromServer" ascii
        $s6 = "webSocket" ascii
        $s7 = "wmCopyData" ascii
        $s8 = "tempStorage" ascii

        $class_1 = "SMNetPage" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (($s1 and 5 of ($s*)) or ($class_1 and 3 of ($s*)))
}

rule APT_Turla_STOCKSTAY_CryptoContainer
{
    meta:
        description = "Detects STOCKSTAY CryptoContainer parsing code used for encrypted C2 communication with RSA and AES"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "82707cfdf24dcb762f4615f01e1ba4d3dfdec4abe9cd588558d2634d7e6a5eeb"
        tlp = "WHITE"
        severity = "high"

    strings:
        $s1 = "BuildCryptoContainer" ascii
        $s2 = "ParseCryptoContainer" ascii
        $s3 = "Windows-1251" wide
        $s4 = "AesCryptoServiceProvider" ascii
        $s5 = "RSACryptoServiceProvider" ascii

    condition:
        uint16(0) == 0x5A4D and
        all of them
}

rule APT_Turla_STOCKSTAY_MARKETMAKER_Downloader
{
    meta:
        description = "Detects STOCKSTAY.MARKETMAKER downloader based on method names and payload filenames used for initial deployment"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "da8a96bc74e265f945f1cc6992c6dc0f9ea36ed1991f7b8d312db79d9bf78c40"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $f1 = "CheckAutoRun" ascii
        $f2 = "SetupAutoRun" ascii
        $f3 = "DownloadAndExtractZip" ascii
        $f4 = "GetSystemProxy" ascii

        $s0 = "_CorExeMain" ascii
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s2 = "StockMarketView.exe" wide
        $s3 = "SMNet.exe" wide
        $s4 = "SMEditor.exe" wide

    condition:
        uint16(0) == 0x5A4D and
        all of ($f*) and $s0 and 2 of ($s*)
}

rule APT_Turla_STOCKSTAY_K1MORPHER_Obfuscation
{
    meta:
        description = "Detects K1.Morpher obfuscation class used by STOCKSTAY and Kazuar backdoors for string encryption via Squirrel3 PRNG"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        hash = "45bb8d1ab2c13bf4354294e13d3c9be15de625d807301905b98462f43f93e893"
        tlp = "WHITE"
        severity = "high"

    strings:
        $api_1 = "Squirrel3" ascii
        $api_2 = "DecryptArraySimple" ascii
        $api_3 = "DecryptIntSimple" ascii
        $api_4 = "DecryptLongSimple" ascii
        $api_5 = "DecryptFloatSimple" ascii
        $api_6 = "DecryptStringSimple" ascii
        $api_7 = "DecryptDoubleSimple" ascii
        $api_8 = "_squ_ui1" ascii
        $api_9 = "_squ_ui2" ascii
        $api_10 = "_squ_ui3" ascii
        $api_11 = "InjectedSeedCipher" ascii

    condition:
        uint16(0) == 0x5A4D and
        5 of ($api*)
}

rule APT_Turla_STOCKSTAY_Config_Plaintext
{
    meta:
        description = "Detects plaintext STOCKSTAY configuration files containing internal IDs, service endpoints, and operational parameters"
        author = "Actioner"
        date = "2026-06-29"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"
        tlp = "WHITE"
        severity = "high"

    strings:
        $id1 = "\"internal_id\"" ascii
        $id2 = "\"i_id\"" ascii
        $key1 = "\"internal_key\"" ascii
        $key2 = "\"i_k\"" ascii
        $eng1 = "\"interval_engine\"" ascii
        $eng2 = "\"ie\"" ascii
        $srv1 = "\"service\"" ascii
        $srv2 = "\"srv\"" ascii
        $dnw1 = "\"days_not_work\"" ascii
        $dnw2 = "\"dnw\"" ascii
        $sp1 = "\"system_properties\"" ascii
        $sp2 = "\"sp\"" ascii

    condition:
        filesize < 100KB and
        any of ($id*) and
        any of ($key*) and
        any of ($eng*) and
        any of ($srv*) and
        any of ($dnw*) and
        any of ($sp*)
}
