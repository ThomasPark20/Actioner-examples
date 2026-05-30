rule MiniShaiHulud_AntV_Payload
{
    meta:
        description = "Detects Mini Shai-Hulud (@antv) npm supply-chain stager/payload (setup_bun.js, bun_environment.js, index.js) via distinctive exfil markers, dead-man-switch token names, runner memory-scrape command, and C2/Session pairing"
        author = "Actioner"
        date = "2026-05-30"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/"
        hash = "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c"
        hash = "fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142"
    strings:
        $repo_desc   = "niagA oG eW ereH :duluH-iahS" ascii wide
        $token_nuke  = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner" ascii wide nocase
        $token_nuke2 = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner" ascii wide nocase
        $scrape_grep = "grep -aoE" ascii
        $scrape_trd  = "tr -d" ascii
        $scrape_pat  = "\":{\"value\":\"" ascii
        $c2          = "t.m-kosche.com" ascii wide nocase
        $session     = "filev2.getsession.org" ascii wide nocase
        $sudoers     = "runner ALL=(ALL) NOPASSWD:ALL" ascii
    condition:
        any of ($repo_desc, $token_nuke, $token_nuke2)
        or (all of ($scrape_grep, $scrape_trd, $scrape_pat))
        or ($c2 and $session)
        or ($sudoers and ($c2 or $session))
}
