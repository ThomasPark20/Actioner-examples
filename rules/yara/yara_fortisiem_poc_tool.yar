rule CVE_2026_106173_FortiSIEM_PoC_Tool
{
    meta:
        description = "Detects CVE-2026-106173 FortiSIEM gRPC path traversal PoC exploit tool by Horizon3.ai"
        author = "Actioner"
        date = "2026-10-21"
        reference = "https://github.com/horizon3ai/CVE-2026-106173"

    strings:
        $rpc_path = "/phoenix.phoenixSvc/SendQueryResult" ascii
        $rce_target = "/opt/charting/redishb.sh" ascii
        $cve_id = "CVE-2026-106173" ascii
        $traversal_func = "def traversal(" ascii
        $grpc_func = "def grpc_message(" ascii
        $overwrite_func = "def overwrite_file(" ascii

    condition:
        uint32(0) != 0x464C457F and 1 of ($traversal_func, $grpc_func, $overwrite_func) and 2 of ($rpc_path, $rce_target, $cve_id)
}
