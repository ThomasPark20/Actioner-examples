rule SupplyChain_LiteLLM_CookPayload_Decoded
{
    meta:
        description = "LiteLLM 1.107.0 privcollect stealer / remote code loader, DECODED or in-memory form only (on-disk cook.py and sitecustomize.py are Base64+zlib and will not match)"
        author = "Actioner"
        date = "2026-10-23"
        reference = "https://socket.dev/blog/litellm-compromise"
        scope = "process memory, decoded payload dumps, sandbox captures"
        validation = "synthetic positives only; not validated on a real sample"

    strings:
        $env_marker = "PRIVCOLLECT_ACTIVE" ascii
        $marker_path = ".pc_once_72129118c59f5636c0bb" ascii
        $lock_path = "remote_code_loader.lock" ascii
        $exfil_header = "XWiA8gZNa7NcX2XRoAEb" ascii
        $deaddrop_repo = "letters9813/pythonclient-test" ascii
        $deaddrop_file = "domain.txt" ascii

    condition:
        filesize < 200KB and
        (
            2 of ($env_marker, $marker_path, $lock_path, $exfil_header) or
            ($deaddrop_repo and $deaddrop_file)
        )
}

rule SupplyChain_LiteLLM_WheelIOCs
{
    meta:
        description = "Malicious litellm-1.107.0 wheel (zip) carrying cook.pth/cook.py/sitecustomize.py under .data/purelib/"
        author = "Actioner"
        date = "2026-10-23"
        reference = "https://socket.dev/blog/litellm-compromise"
        validation = "synthetic zip only; not validated on a real wheel"

    strings:
        $cook_pth = "litellm-1.107.0.data/purelib/cook.pth" ascii
        $cook_py = "litellm-1.107.0.data/purelib/cook.py" ascii
        $sitecustomize = "litellm-1.107.0.data/purelib/sitecustomize.py" ascii

    condition:
        uint32(0) == 0x04034b50 and filesize < 50MB and 2 of them
}
