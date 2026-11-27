import "hash"

rule SoftwareOK_Supply_Chain_Trojanized_Installer
{
    meta:
        description = "Detects trojanized Q-Dir and DesktopOK installers from the SoftwareOK supply chain attack based on SHA-256 hashes"
        author = "Actioner"
        date = "2026-11-27"
        reference = "https://asec.ahnlab.com/en/96827/"
        hash1 = "434b67dd403c74752b336fbb4fc94ee3a6fb615168e3fd31baea71d1a356ecd8"
        hash2 = "8ac6901a941788ab9675a9ec9bebdbc00074cb76f19a7d84c2e1b0ddbcee4f48"
        hash3 = "cf9e2433540d0b8ae8c9f4c9d5f11770343d413c1cfb201c5edae7155f88585a"
        hash4 = "d1a2cf8882c254156848f4a12b6c6837a3cf0e460f876c6f8b00d32a1560640a"
        hash5 = "7afa1e77c115eaa7798237039fde67c8a69686e7d9a4034a8df54aff2d1a126d"
        hash6 = "1b7b7947527a05f0fae268b16894440549c2dd512d421a06960e27b5fb1d5fa0"
        hash7 = "c41bd9eefd7a63fa329b24144a3483abac012ebc11bd5606b6c8295251d46422"
        hash8 = "551e5744b24019f016f9ee8dd3a2c00429da587b20321abaef55c18c0a655a5d"
        hash9 = "7524fcf3ffc44fc2e9a53af761c2a308edac31d02df3dfb1a4b57504243aec48"
        hash10 = "b45ba4a1d9a25116b94e95ef48d63fffda7d77bd358d17d74c7575ce39986b84"
        hash11 = "c12651f2988bb5e05afd1f4b1e6bce618111a4703f1aadc006bfacc6ac7e1d90"
        hash12 = "f96cab94d9f0e0000dfef8b9fce16bcefd23679443cc8ba8f7811a55ea5799ec"
        hash13 = "8c172c421129bda890b504e89d1bb72af477be9896b22a576920c050442b4a04"
        hash14 = "5b43284e48edee4acbab49bc5a68eb21d3a369a058d859689b6a5dd2042a5e2a"
        hash15 = "bdbbe28cde3dee061536e524bc2a14316015db0c958cad83023790d32a4f8d99"
        hash16 = "393d2f9f05affa88aaa19f29f041d28fe5c3e1fc2fd84c76d1e2f1aa6da74a83"
        hash17 = "ff4ec1cca4746e33d1205ed434e1e2ac9cee71fec477b032f56d3bde577626d2"

    condition:
        hash.sha256(0, filesize) == "434b67dd403c74752b336fbb4fc94ee3a6fb615168e3fd31baea71d1a356ecd8" or
        hash.sha256(0, filesize) == "8ac6901a941788ab9675a9ec9bebdbc00074cb76f19a7d84c2e1b0ddbcee4f48" or
        hash.sha256(0, filesize) == "cf9e2433540d0b8ae8c9f4c9d5f11770343d413c1cfb201c5edae7155f88585a" or
        hash.sha256(0, filesize) == "d1a2cf8882c254156848f4a12b6c6837a3cf0e460f876c6f8b00d32a1560640a" or
        hash.sha256(0, filesize) == "7afa1e77c115eaa7798237039fde67c8a69686e7d9a4034a8df54aff2d1a126d" or
        hash.sha256(0, filesize) == "1b7b7947527a05f0fae268b16894440549c2dd512d421a06960e27b5fb1d5fa0" or
        hash.sha256(0, filesize) == "c41bd9eefd7a63fa329b24144a3483abac012ebc11bd5606b6c8295251d46422" or
        hash.sha256(0, filesize) == "551e5744b24019f016f9ee8dd3a2c00429da587b20321abaef55c18c0a655a5d" or
        hash.sha256(0, filesize) == "7524fcf3ffc44fc2e9a53af761c2a308edac31d02df3dfb1a4b57504243aec48" or
        hash.sha256(0, filesize) == "b45ba4a1d9a25116b94e95ef48d63fffda7d77bd358d17d74c7575ce39986b84" or
        hash.sha256(0, filesize) == "c12651f2988bb5e05afd1f4b1e6bce618111a4703f1aadc006bfacc6ac7e1d90" or
        hash.sha256(0, filesize) == "f96cab94d9f0e0000dfef8b9fce16bcefd23679443cc8ba8f7811a55ea5799ec" or
        hash.sha256(0, filesize) == "8c172c421129bda890b504e89d1bb72af477be9896b22a576920c050442b4a04" or
        hash.sha256(0, filesize) == "5b43284e48edee4acbab49bc5a68eb21d3a369a058d859689b6a5dd2042a5e2a" or
        hash.sha256(0, filesize) == "bdbbe28cde3dee061536e524bc2a14316015db0c958cad83023790d32a4f8d99" or
        hash.sha256(0, filesize) == "393d2f9f05affa88aaa19f29f041d28fe5c3e1fc2fd84c76d1e2f1aa6da74a83" or
        hash.sha256(0, filesize) == "ff4ec1cca4746e33d1205ed434e1e2ac9cee71fec477b032f56d3bde577626d2"
}

rule SoftwareOK_Supply_Chain_Python_RAT_Strings
{
    meta:
        description = "Detects the Python RAT payload deployed by trojanized SoftwareOK installers based on distinctive strings"
        author = "Actioner"
        date = "2026-11-27"
        reference = "https://asec.ahnlab.com/en/96827/"

    strings:
        $s1 = "py_client_dsv2" ascii wide
        $s2 = "dsv2_py39_agent" ascii wide
        $s3 = "DeviceSync" ascii wide
        $s4 = "MicrosoftEdge_dcntel" ascii wide
        $url1 = "mail.c1a2.top" ascii wide
        $url2 = "/dl/dsv2_py39_agent.7z" ascii wide
        $url3 = "/dl/7zr.exe" ascii wide
        $c2 = "8.210.69.51" ascii wide
        $port = "9876" ascii wide

    condition:
        (3 of ($s*)) or
        ($url1 and ($url2 or $url3)) or
        ($c2 and $port and 1 of ($s*))
}

rule SoftwareOK_Supply_Chain_RAT_Script
{
    meta:
        description = "Detects the py_client_dsv2.py RAT script used in the SoftwareOK supply chain attack"
        author = "Actioner"
        date = "2026-11-27"
        reference = "https://asec.ahnlab.com/en/96827/"

    strings:
        $header = "py_client_dsv2" ascii
        $c2_ip = "8.210.69.51" ascii
        $c2_port = "9876" ascii
        $fn1 = "screenshot" ascii nocase
        $fn2 = "shell" ascii nocase
        $fn3 = "upload" ascii nocase
        $fn4 = "download" ascii nocase
        $fn5 = "sysinfo" ascii nocase

    condition:
        $header and $c2_ip and $c2_port and 2 of ($fn*)
}
