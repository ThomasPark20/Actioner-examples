import "pe"
import "hash"

rule Rapuncel_Alinubx_BYOVD_Driver {
    meta:
        description = "Detects Alinubx.sys BYOVD driver (renamed CcProtect.sys) used in Rapuncel campaign to terminate security products"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        reference2 = "https://www.loldrivers.io/drivers/84a3007a-de5e-4622-bfc5-f05d927c3618/"
        hash1 = "611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $device_path = "\\\\.\\Alinubx" wide ascii
        $original_name = "CcProtect" wide ascii
        $publisher = "CnCrypt" wide ascii
        $dafeng = "Henan Dafeng" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            2 of ($device_path, $original_name, $publisher, $dafeng) or
            hash.sha256(0, filesize) == "611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61" or
            hash.sha256(0, filesize) == "5f0cfe8357bb52b45068ddbac053e32bc38e6cb5e086746f5402657b0a5cfb1c"
        )
}

rule Rapuncel_Cruciferra_Loader {
    meta:
        description = "Detects vsdbg.dll loader built with Cruciferra PUROSANGUE crypter used in Rapuncel campaign"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        hash1 = "ea8c31a86fa785ab514022c278a2f6e571c86aac9283745a96605c44d88382d6"
        severity = "critical"

    strings:
        $build_path = "ExploitTests\\purosangue" ascii nocase
        $custom_b16 = { 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F }
        $reloc_payload = ".reloc" ascii
        $vsdbg_name = "vsdbg.dll" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            $build_path or
            ($custom_b16 and $reloc_payload and $vsdbg_name and pe.number_of_sections > 4) or
            hash.sha256(0, filesize) == "ea8c31a86fa785ab514022c278a2f6e571c86aac9283745a96605c44d88382d6"
        )
}

rule Rapuncel_Stealer_Payload {
    meta:
        description = "Detects Rapuncel infostealer payload targeting browsers, crypto wallets, and messaging apps"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        hash1 = "aefbc6e04320e9a0e80f2323f8a897c4fdb222a37b0b87d76e850109decbfadd"
        severity = "critical"

    strings:
        $log1 = "browser_decryption.log" ascii wide
        $log2 = "sends.log" ascii wide
        $artifact1 = "UserInformation.txt" ascii wide
        $artifact2 = "installed_applications.txt" ascii wide
        $artifact3 = "Filegraber" ascii wide
        $harvest1 = "PreferenceMACs" ascii wide
        $harvest2 = "extensions.settings" ascii wide
        $upload = "/upload" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            (3 of ($log1, $log2, $artifact1, $artifact2, $artifact3)) or
            ($harvest1 and $harvest2 and $upload) or
            hash.sha256(0, filesize) == "aefbc6e04320e9a0e80f2323f8a897c4fdb222a37b0b87d76e850109decbfadd"
        )
}

rule Rapuncel_Browser_Injection_DLL {
    meta:
        description = "Detects the browser injection DLL used by Rapuncel to bypass Chrome app-bound encryption"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        hash1 = "75018b06c7105a1dca391805d17b402aed35ebd515b92d461236eafbd606cb40"
        severity = "high"

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            hash.sha256(0, filesize) == "75018b06c7105a1dca391805d17b402aed35ebd515b92d461236eafbd606cb40" or
            hash.sha256(0, filesize) == "26db14b956e33f69b3397a36387d32e01eb63613acff91069dc76b6ed7de45a8"
        )
}

rule Rapuncel_Fake_LastPass_Archive {
    meta:
        description = "Detects fake LastPass Authenticator installer archives used for Rapuncel distribution"
        author = "Actioner"
        date = "2026-09-22"
        reference = "https://blog.lastpass.com/posts/lastpass-delphos-report-rapuncel-infostealer"
        severity = "high"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $lp_name1 = "LastPass-Authenticator" ascii wide
        $lp_name2 = "lastpass-authenticator" ascii wide
        $junk1 = "TitanStorage.dll" ascii wide
        $junk2 = "ProManager.dll" ascii wide
        $vsdbg = "vsdbg" ascii wide

    condition:
        $zip_magic at 0 and
        filesize > 100MB and
        (1 of ($lp_name*)) and
        (1 of ($junk*) or $vsdbg)
}
