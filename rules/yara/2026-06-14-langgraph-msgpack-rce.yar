rule Exploit_CVE_2026_28277_LangGraph_Msgpack_RCE
{
    meta:
        description = "Detects exploit scripts targeting CVE-2026-28277 LangGraph unsafe msgpack deserialization via ext_hook for arbitrary code execution"
        author = "Actioner"
        date = "2026-06-14"
        reference = "https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/"
        severity = "high"

    strings:
        $hook1 = "_msgpack_ext_hook" ascii
        $hook2 = "EXT_CONSTRUCTOR_SINGLE_ARG" ascii
        $hook3 = "ext_hook" ascii

        $deser1 = "ormsgpack.unpackb" ascii
        $deser2 = "msgpack.unpackb" ascii
        $deser3 = "importlib.import_module" ascii

        $rce1 = "os.system" ascii
        $rce2 = "subprocess" ascii
        $rce3 = "__import__" ascii

        $ctx1 = "langgraph" ascii
        $ctx2 = "checkpoint" ascii
        $ctx3 = "loads_typed" ascii

    condition:
        filesize < 1MB and
        (2 of ($hook*) or (1 of ($hook1, $hook2) and 1 of ($deser*))) and
        (1 of ($rce*)) and
        (1 of ($ctx*))
}
