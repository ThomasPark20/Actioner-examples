rule Malware_AhsayCBS_Python_Backdoor_MainPy
{
    meta:
        description = "Detects the AhsayCBS Python backdoor (main.py) via distinctive obfuscation and sandbox-evasion strings"
        author = "Actioner"
        date = "2026-11-12"
        reference = "https://www.huntress.com/blog/ahsaycbs-webshells"
        hash = "8aac187bae71f75fa2dde03dcb4a9279c982182ee8254ae96e7a6626fe4c7617"
        severity = "critical"

    strings:
        $source_name = "heap_shellcode_runner_bound_weaponized" ascii
        $machine_guid = "MachineGuid" ascii wide
        $heap_create = "HeapCreate" ascii
        $heap_alloc = "HeapAlloc" ascii
        $rtl_move = "RtlMoveMemory" ascii
        $create_thread = "CreateThread" ascii
        $marshal = "marshal" ascii
        $lzma = "lzma" ascii

    condition:
        filesize < 5MB and
        $source_name and
        $machine_guid and
        2 of ($heap_create, $heap_alloc, $rtl_move, $create_thread) and
        1 of ($marshal, $lzma)
}
