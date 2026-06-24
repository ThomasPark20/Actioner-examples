rule Malware_GlassWASM_TinyGo_WASM_Loader
{
    meta:
        description = "Detects GlassWASM TinyGo-compiled WebAssembly loader used in trojanized Open VSX extensions. Matches the combination of TinyGo WASM runtime exports, Go JS bridge imports, and ChaCha20 encryption constant."
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash = "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
        tlp = "WHITE"
        severity = "high"

    strings:
        // WASM magic bytes
        $wasm_magic = { 00 61 73 6D }

        // TinyGo runtime exports (present in cleartext as WASM export names)
        $export_asyncify_start = "asyncify_start_unwind" ascii
        $export_asyncify_stop = "asyncify_stop_rewind" ascii
        $export_go_sched = "go_scheduler" ascii

        // Go JS bridge imports (present in cleartext as WASM import names)
        $import_valueGet = "gojs.syscall/js.valueGet" ascii
        $import_valueCall = "gojs.syscall/js.valueCall" ascii
        $import_valueInvoke = "gojs.syscall/js.valueInvoke" ascii
        $import_valueNew = "gojs.syscall/js.valueNew" ascii
        $import_stringVal = "gojs.syscall/js.stringVal" ascii

        // ChaCha20 constant (present in cleartext as part of the cipher implementation)
        $chacha = "expand 32-byte k" ascii

    condition:
        // NOTE: Solana method names (getSignaturesForAddress, getTransaction) and
        // child_process/execSync strings are ChaCha20-encrypted at rest in the WASM
        // binary and only decrypted at runtime. They are NOT matchable by YARA.
        // Detection relies on TinyGo export/import fingerprint + ChaCha20 constant.
        $wasm_magic at 0 and
        filesize > 500KB and filesize < 2MB and
        2 of ($export_*) and
        3 of ($import_*) and
        $chacha
}

rule Malware_GlassWASM_VSIX_Package
{
    meta:
        description = "Detects GlassWASM malicious VSIX extension packages by SHA256 hash of known samples."
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash = "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58"
        tlp = "WHITE"
        severity = "critical"

    strings:
        // VSIX is a ZIP file
        $zip_magic = { 50 4B 03 04 }

        // Extension manifest markers
        $ext1 = "vsblack" ascii
        $ext2 = "flint-debug" ascii

        // WASM file reference inside VSIX
        $wasm_ref1 = "snqpkebiwrxmoivl.wasm" ascii
        $wasm_ref2 = "orybbbdsuqmaapel.wasm" ascii

    condition:
        $zip_magic at 0 and
        (1 of ($ext*) and 1 of ($wasm_ref*))
}

import "hash"

rule Malware_GlassWASM_WASM_Module_Hash
{
    meta:
        description = "Detects the specific GlassWASM WASM payload by file hash."
        author = "Actioner"
        date = "2026-06-20"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash = "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $wasm_magic = { 00 61 73 6D }

    condition:
        $wasm_magic at 0 and
        filesize == 824552 and
        hash.sha256(0, filesize) == "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
}
