import "hash"

rule GlassWASM_WASM_Payload
{
    meta:
        description = "Detects GlassWASM TinyGo-compiled WebAssembly payload by known hashes and structural indicators"
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash1 = "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
        severity = "high"
        note = "String branches ($solana*, $cp*) target unencrypted or partially decrypted variants. The production payload encrypts these strings with ChaCha20 at rest; they become visible only during dynamic analysis or if encryption is disabled in future builds."

    strings:
        // WebAssembly magic bytes
        $wasm_magic = { 00 61 73 6D 01 00 00 00 }

        // TinyGo gojs bridge imports
        $tinygo_import1 = "gojs.syscall/js.valueCall" ascii
        $tinygo_import2 = "gojs.syscall/js.valueInvoke" ascii
        $tinygo_import3 = "gojs.runtime.ticks" ascii

        // ChaCha20 sigma constant
        $chacha_sigma = "expand 32-byte k" ascii

        // Solana-related strings (visible in unencrypted variants or memory dumps)
        $solana1 = "getSignaturesForAddress" ascii
        $solana2 = "getTransaction" ascii
        $solana3 = "spl-memo" ascii

        // child_process abuse indicators (visible in unencrypted variants or memory dumps)
        $cp1 = "child_process" ascii
        $cp2 = "execSync" ascii
        $cp3 = "windowsHide" ascii

    condition:
        $wasm_magic at 0 and
        (
            // Known hash match
            hash.sha256(0, filesize) == "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f"
            or
            // TinyGo WASM with ChaCha20 and child_process indicators
            (2 of ($tinygo_import*) and $chacha_sigma and 2 of ($cp*))
            or
            // TinyGo WASM with Solana C2 indicators
            (2 of ($tinygo_import*) and 2 of ($solana*))
        )
}

rule GlassWASM_VSIX_Package
{
    meta:
        description = "Detects known trojanized VSIX packages delivering GlassWASM payload"
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        hash1 = "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58"
        hash2 = "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25"
        severity = "critical"

    strings:
        // VSIX is a ZIP-based format
        $pk_header = { 50 4B 03 04 }

        // Extension identifiers (case-sensitive -- these are npm-style package names)
        $ext1 = "vsblack" ascii
        $ext2 = "flint-debug" ascii

        // WASM payload filenames
        $wasm_file1 = "snqpkebiwrxmoivl.wasm" ascii
        $wasm_file2 = "orybbbdsuqmaapel.wasm" ascii

        // onStartupFinished activation
        $activation = "onStartupFinished" ascii

    condition:
        $pk_header at 0 and
        (
            hash.sha256(0, filesize) == "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58" or
            hash.sha256(0, filesize) == "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25" or
            (1 of ($wasm_file*) and $activation) or
            (1 of ($ext*) and 1 of ($wasm_file*))
        )
}

rule GlassWASM_TinyGo_WASM_Suspicious
{
    meta:
        description = "Detects suspicious TinyGo-compiled WASM files with encryption and process execution imports - behavioral heuristic"
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://socket.dev/blog/glasswasm-malware-open-vsx-extensions"
        severity = "low"
        note = "The ChaCha20 sigma constant alone is common in cryptographic binaries. This rule requires WASM-specific structural indicators (TinyGo imports, asyncify exports, WASI imports) to reduce false positives."

    strings:
        $wasm_magic = { 00 61 73 6D 01 00 00 00 }

        // TinyGo imports
        $tg1 = "gojs.syscall/js" ascii
        $tg2 = "go_scheduler" ascii

        // asyncify exports (TinyGo async support)
        $async1 = "asyncify_start_unwind" ascii
        $async2 = "asyncify_stop_unwind" ascii
        $async3 = "asyncify_start_rewind" ascii

        // ChaCha20 indicator
        $chacha = "expand 32-byte k" ascii

        // WASI imports
        $wasi1 = "fd_write" ascii
        $wasi2 = "proc_exit" ascii
        $wasi3 = "random_get" ascii

    condition:
        $wasm_magic at 0 and
        filesize > 500KB and filesize < 2MB and
        1 of ($tg*) and
        2 of ($async*) and
        $chacha and
        2 of ($wasi*)
}
