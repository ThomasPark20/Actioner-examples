rule Exploit_AutoJack_MCP_WebSocket_Payload
{
    meta:
        description = "Detects HTML/JavaScript payloads crafted to exploit the AutoJack vulnerability by opening a WebSocket to the AutoGen Studio MCP endpoint with base64-encoded StdioServerParams for arbitrary command execution"
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/06/18/autojack-single-page-rce-host-running-ai-agent/"
        severity = "high"

    strings:
        $ws1 = "ws://localhost:8081/api/mcp/ws/" ascii wide nocase
        $ws2 = "ws://127.0.0.1:8081/api/mcp/ws/" ascii wide nocase
        $ws3 = "ws://localhost:8080/api/mcp/ws/" ascii wide nocase
        $ws4 = "ws://127.0.0.1:8080/api/mcp/ws/" ascii wide nocase
        $param = "server_params=" ascii wide nocase
        $type1 = "StdioServerParams" ascii wide
        $type2 = "U3RkaW9TZXJ2ZXJQYXJhbXM" ascii wide
        $func1 = "WebSocket" ascii wide
        $func2 = "new WebSocket" ascii wide
        $func3 = "btoa" ascii wide
        $func4 = "base64" ascii wide nocase

    condition:
        filesize < 1MB and
        (1 of ($ws*)) and
        ($param) and
        (1 of ($type*) or 1 of ($func*))
}
