rule Proto6_Malicious_Protobuf_Schema_Code_Injection
{
    meta:
        description = "Detects crafted .proto or JSON descriptor files attempting code injection via protobuf.js Proto6 vulnerabilities (CVE-2026-44291, CVE-2026-44293, CVE-2026-44295, CVE-2026-44294)"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://thehackernews.com/2026/06/six-proto6-vulnerabilities-in.html"
        severity = "high"

    strings:
        // Code injection attempts in schema names, field names, or type references
        // These patterns target CVE-2026-44295 (pbjs static output injection) and
        // CVE-2026-44291 (type name injection into Function() generated code)
        $inject1 = "require(" ascii nocase
        $inject2 = "eval(" ascii nocase
        $inject3 = "Function(" ascii nocase
        $inject4 = "child_process" ascii
        $inject5 = "process.env" ascii
        $inject6 = "process.exit" ascii
        $inject7 = "constructor[" ascii
        $inject8 = "__proto__" ascii
        $inject9 = ".prototype." ascii

        // Protobuf schema markers — trailing space ensures proto syntax context
        $proto_syntax = "syntax" ascii
        $proto_msg = "message " ascii
        $proto_pkg = "package" ascii
        $proto_svc = "service" ascii
        $proto_enum = "enum" ascii

        // JSON descriptor markers (for reflection API attacks)
        $json_nested = "\"nested\"" ascii
        $json_fields = "\"fields\"" ascii

    condition:
        filesize < 1MB and
        (
            // Proto file with injection attempts
            (
                ($proto_syntax or $proto_msg or $proto_pkg or $proto_svc or $proto_enum) and
                2 of ($inject*)
            )
            or
            // JSON descriptor with injection attempts
            (
                ($json_nested and $json_fields) and
                2 of ($inject*)
            )
        )
}

rule Proto6_Malicious_Bytes_Default_Injection
{
    meta:
        description = "Detects crafted protobuf JSON descriptors with code injection in bytes field defaults (CVE-2026-44293)"
        author = "Actioner"
        date = "2026-06-10"
        reference = "https://github.com/protobufjs/protobuf.js/security/advisories/GHSA-66ff-xgx4-vchm"
        severity = "high"

    strings:
        $json_fields = "\"fields\"" ascii
        $json_type_bytes = "\"bytes\"" ascii
        $json_default = "\"default\"" ascii

        // Injection payloads in default values
        $payload1 = "require(" ascii
        $payload2 = "eval(" ascii
        $payload3 = "Function(" ascii
        $payload4 = "process.mainModule" ascii
        $payload5 = "child_process" ascii
        $payload6 = "execSync" ascii
        $payload7 = "spawnSync" ascii

    condition:
        filesize < 1MB and
        $json_fields and $json_type_bytes and $json_default and
        1 of ($payload*)
}
