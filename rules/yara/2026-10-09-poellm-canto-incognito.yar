rule PoeLLM_Libgcrypt_ELF
{
    meta:
        description = "Detects the PoeLLM malware ELF binary masquerading as libgcrypt, used in the Canto Incognito botnet campaign"
        author = "Actioner"
        date = "2026-10-09"
        reference = "https://www.bleepingcomputer.com/news/security/poellm-malware-infects-exposed-ai-servers-in-cryptomining-attacks/"
        reference2 = "https://thehackernews.com/2026/10/poellm-malware-infects-3400-servers-to.html"
        tlp = "WHITE"
        severity = "high"

    strings:
        // ELF magic
        $elf_magic = { 7F 45 4C 46 }

        // Poem-based C2 derivation strings
        $poem_title = "On the Nature of Connection" ascii
        $poem_fetch = "dash.css" ascii
        // Word-to-number dictionary entries (C2 address derivation)
        $dict_word1 = "through" ascii
        $dict_word2 = "silence" ascii
        $dict_word3 = "between" ascii
        $dict_word4 = "whisper" ascii
        $dict_word5 = "beneath" ascii

        // Miner-related strings
        $miner1 = "xmrig" ascii nocase
        $miner2 = "kryptex" ascii nocase
        $miner3 = "stratum" ascii

        // Scanning / propagation targets
        $target1 = "litellm" ascii nocase
        $target2 = "gotenberg" ascii nocase

        // Binary name masquerading
        $masquerade = "libgcrypt" ascii

        // Remote shell
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii

    condition:
        $elf_magic at 0 and
        $masquerade and
        (
            ($poem_title or $poem_fetch) or
            (2 of ($dict_word*)) or
            (1 of ($miner*) and 1 of ($target*))
        ) and
        (1 of ($shell*))
}
