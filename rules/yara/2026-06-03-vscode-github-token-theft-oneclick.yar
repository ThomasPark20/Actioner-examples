rule Exploit_VSCode_GithubDev_Token_Theft_OneClick
{
    meta:
        description = "Detects the github.dev one-click GitHub token theft PoC artifacts: a malicious workspace .vscode extension that maps a keybinding to workbench.extensions.installExtension with skipPublisherTrust, and/or the notebook webview payload that synthesizes did-keydown events to silently install the second-stage extension"
        author = "Actioner"
        date = "2026-06-03"
        reference = "https://blog.ammaraskar.com/github-token-stealing/"
        tlp = "WHITE"
        severity = "high"

    strings:
        // --- Malicious workspace extension manifest (.vscode/extensions/*/package.json) ---
        $m_install   = "workbench.extensions.installExtension" ascii
        $m_skiptrust = "skipPublisherTrust" ascii
        $m_target    = "AmmarTest.hello-ammar-github" ascii
        $m_runcmds   = "runCommands" ascii
        $m_keybind   = "ctrl+f1" ascii nocase

        // --- Malicious notebook / webview payload (did-keydown injection) ---
        $p_imgerr    = "onerror=" ascii nocase
        $p_kbevent   = "new KeyboardEvent" ascii
        $p_keydown   = "\"keydown\"" ascii
        $p_secondrun = "secondRun" ascii
        $p_combo     = "ctrlKey: true, shiftKey: true" ascii
        $p_dataimg   = "data:foobar" ascii

    condition:
        filesize < 200KB and
        (
            // manifest variant: silent install + trust bypass
            ($m_install and $m_skiptrust and ($m_target or $m_runcmds or $m_keybind))
            or
            // payload variant: synthetic keystroke injection in a webview/notebook
            ($p_kbevent and $p_keydown and ($p_secondrun or $p_combo or $p_dataimg))
            or
            // notebook image onerror handler delivering the keystroke payload
            ($p_imgerr and $p_dataimg and $p_kbevent)
        )
}
