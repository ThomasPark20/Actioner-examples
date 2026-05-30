rule npm_colortoolsv2_malicious_package
{
    meta:
        description = "Malicious npm packages colortoolsv2 / mimelib2 (ReversingLabs, 2025) detected by manifest package name; Ethereum-smart-contract downloader campaign."
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.reversinglabs.com/blog/ethereum-contracts-malicious-code"
        hash = "678c20775ff86b014ae8d9869ce5c41ee06b6215"
    strings:
        $name1 = "\"name\": \"colortoolsv2\"" ascii nocase
        $name2 = "\"name\":\"colortoolsv2\"" ascii nocase
        $name3 = "\"name\": \"mimelib2\"" ascii nocase
        $name4 = "\"name\":\"mimelib2\"" ascii nocase
    condition:
        filesize < 64KB and any of them
}
