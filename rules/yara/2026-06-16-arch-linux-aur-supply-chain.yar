/*
    Atomic Arch AUR Supply Chain Attack - YARA Rules
    Date: 2026-06-16
    Reference: https://ioctl.fail/preliminary-analysis-of-aur-malware/
    TLP: WHITE
*/

rule AtomicArch_Deps_Infostealer
{
    meta:
        description = "Detects the Atomic Arch deps ELF infostealer binary by hash and characteristic strings"
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://ioctl.fail/preliminary-analysis-of-aur-malware/"
        hash1 = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
        hash2 = "7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316"
        hash3 = "47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204"
        tlp = "white"
        confidence = "high"

    strings:
        $elf_magic = { 7F 45 4C 46 }

        // C2 and exfil strings
        $s_api_agent = "/api/agent" ascii
        $s_upload = "/upload" ascii
        $s_tempsh = "temp.sh" ascii

        // SOCKS proxy strings
        $s_socks_greeting = "socks greeting write" ascii
        $s_socks_connect = "socks CONNECT failed" ascii

        // eBPF loader strings
        $s_bpf_load = "bpf_object__load" ascii
        $s_bpf_attach = "bpf_program__attach" ascii
        $s_bpf_pin = "bpf_map__pin" ascii
        $s_scales = "scales.bpf.c" ascii

        // BPF map names
        $s_hidden_pids = "hidden_pids" ascii
        $s_hidden_names = "hidden_names" ascii
        $s_hidden_inodes = "hidden_inodes" ascii

        // Credential targeting strings
        $s_vault_token = ".vault-token" ascii
        $s_docker_config = ".docker/config.json" ascii
        $s_ssh_dir = ".ssh/" ascii

        // Anti-debug
        $s_capeff = "CapEff:" ascii

        // Monero reference
        $s_monero = "monero-wallet-gui" ascii

    condition:
        $elf_magic at 0 and
        (
            // Strong match: C2 + eBPF indicators
            (2 of ($s_api_agent, $s_upload, $s_tempsh) and 2 of ($s_bpf_load, $s_bpf_attach, $s_bpf_pin, $s_scales)) or
            // Strong match: SOCKS + hidden maps
            (1 of ($s_socks_greeting, $s_socks_connect) and 2 of ($s_hidden_pids, $s_hidden_names, $s_hidden_inodes)) or
            // Broad match: multiple indicators from different categories
            (3 of ($s_api_agent, $s_socks_greeting, $s_bpf_load, $s_hidden_pids, $s_vault_token, $s_docker_config, $s_ssh_dir, $s_capeff, $s_monero))
        )
}

rule AtomicArch_eBPF_Rootkit_Strings
{
    meta:
        description = "Detects eBPF rootkit component strings associated with Atomic Arch campaign"
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://ioctl.fail/preliminary-analysis-of-aur-malware/"
        tlp = "white"
        confidence = "high"

    strings:
        $elf_magic = { 7F 45 4C 46 }

        // eBPF rootkit specific strings
        $s_scales = "scales.bpf.c" ascii
        $s_hidden_pids = "hidden_pids" ascii
        $s_hidden_names = "hidden_names" ascii
        $s_hidden_inodes = "hidden_inodes" ascii

        // eBPF API functions
        $s_bpf_load = "bpf_object__load" ascii
        $s_bpf_attach = "bpf_program__attach" ascii
        $s_bpf_pin = "bpf_map__pin" ascii

        // Syscall hooking indicators
        $s_getdents = "getdents64" ascii
        $s_ptrace_attach = "PTRACE_ATTACH" ascii
        $s_ptrace_seize = "PTRACE_SEIZE" ascii
        $s_netlink_diag = "NETLINK_SOCK_DIAG" ascii

    condition:
        $elf_magic at 0 and
        (
            // Direct match: scales.bpf.c source reference with hidden maps
            ($s_scales and 2 of ($s_hidden_pids, $s_hidden_names, $s_hidden_inodes)) or
            // Behavioral match: BPF loading + hiding maps
            (2 of ($s_bpf_load, $s_bpf_attach, $s_bpf_pin) and 2 of ($s_hidden_pids, $s_hidden_names, $s_hidden_inodes)) or
            // Anti-forensic match: hiding + anti-debug + syscall hook
            (2 of ($s_hidden_pids, $s_hidden_names, $s_hidden_inodes) and $s_getdents and 1 of ($s_ptrace_attach, $s_ptrace_seize)) or
            // Network concealment match: hiding + netlink diagnostics suppression
            (2 of ($s_hidden_pids, $s_hidden_names, $s_hidden_inodes) and $s_netlink_diag)
        )
}

rule AtomicArch_Malicious_PKGBUILD
{
    meta:
        description = "Detects AUR PKGBUILD or .install files containing Atomic Arch malicious injection commands"
        author = "Actioner"
        date = "2026-06-16"
        reference = "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency"
        tlp = "white"
        confidence = "high"

    strings:
        // Wave 1 injection patterns
        $s_npm_atomic = "npm install atomic-lockfile" ascii nocase
        $s_npm_atomic_full = "npm install atomic-lockfile minimist chalk" ascii nocase

        // Wave 2 injection patterns
        $s_bun_jsdigest = "bun install js-digest" ascii nocase
        $s_npm_lockfilejs = "npm install lockfile-js" ascii nocase

        // Preinstall hook path reference
        $s_hooks_deps = "src/hooks/deps" ascii

        // PKGBUILD context indicators
        $s_pkgbuild = "pkgname=" ascii
        $s_install_hook = ".install" ascii
        $s_post_install = "post_install()" ascii
        $s_pre_install = "pre_install()" ascii

    condition:
        (1 of ($s_npm_atomic, $s_npm_atomic_full, $s_bun_jsdigest, $s_npm_lockfilejs)) or
        ($s_hooks_deps and 1 of ($s_pkgbuild, $s_install_hook, $s_post_install, $s_pre_install))
}
