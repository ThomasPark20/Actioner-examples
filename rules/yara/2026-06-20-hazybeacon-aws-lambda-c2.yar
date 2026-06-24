import "pe"

rule APT_HazyBeacon_Backdoor_mscorsvc
{
    meta:
        description = "Detects HazyBeacon backdoor DLL (mscorsvc.dll) used by CL-STA-1020 for AWS Lambda-based C2"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/"
        hash = "4931df8650521cfd686782919bda0f376475f9fc5f1fee9d7cf3a4e0d9c73e30"
        tlp = "WHITE"
        severity = "high"

    strings:
        $lambda1 = "lambda-url" ascii wide
        $lambda2 = ".on.aws" ascii wide
        $lambda3 = "ap-southeast-1" ascii wide
        $svc1 = "msdnetsvc" ascii wide
        $api1 = "HttpSendRequestA" ascii fullword
        $api2 = "HttpSendRequestW" ascii fullword
        $api3 = "InternetOpenA" ascii fullword
        $api4 = "InternetConnectA" ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (all of ($lambda*)) or
            ($svc1 and 2 of ($api*)) or
            (2 of ($lambda*) and $svc1)
        )
}

rule APT_HazyBeacon_FileCollector_igfx
{
    meta:
        description = "Detects HazyBeacon file collector tool (igfx.exe) used for targeted document harvesting"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/"
        hash = "279e60e77207444c7ec7421e811048267971b0db42f4b4d3e975c7d0af7f511e"
        tlp = "WHITE"
        severity = "high"

    strings:
        $ext1 = ".doc" ascii wide
        $ext2 = ".docx" ascii wide
        $ext3 = ".xlsx" ascii wide
        $ext4 = ".pdf" ascii wide
        $path1 = "ProgramData" ascii wide
        $arch1 = "7z.exe" ascii wide
        $arch2 = "-v200m" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        3 of ($ext*) and
        $path1 and
        $arch1 and
        $arch2
}

rule APT_HazyBeacon_CloudUploader
{
    meta:
        description = "Detects HazyBeacon cloud exfiltration tools targeting Google Drive and Dropbox"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/"
        hash = "d20b536c88ecd326f79d7a9180f41a2e47a40fcf2cc6a2b02d68a081c89eaeaa"
        tlp = "WHITE"
        severity = "high"

    strings:
        $gdrive1 = "googleapis.com/upload" ascii wide
        $gdrive2 = "drive.google.com" ascii wide
        $gdrive3 = "GoogleDriveUpload" ascii wide
        $drop1 = "content.dropboxapi.com" ascii wide
        $drop2 = "api.dropboxapi.com" ascii wide
        $path1 = "ProgramData" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $path1 and
        (2 of ($gdrive*) or 2 of ($drop*))
}
