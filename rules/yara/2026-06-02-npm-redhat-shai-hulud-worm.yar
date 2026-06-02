rule Miasma_ShaiHulud_RedHat_Payload
{
    meta:
        description = "Detects the Miasma ('The Spreading Blight') Shai-Hulud variant Red Hat npm worm loader/stealer (index.js / _index.js) via campaign-unique markers: exfil-repo description, dead-man-switch commit-message token, firedalazer GitHub commit-search C2, api.anthropic.com camouflage exfil path, hardcoded AES-128-GCM keys, and OIDC trusted-publishing workflow markers"
        author = "Actioner"
        date = "2026-06-02"
        reference = "https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/"
        reference2 = "https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages"
        hash = "df1732f5bfec12e066be44dee02ec8a243e4868d38672c1b1d065359dd735a14"
        hash2 = "0dc06ecdaa63fe24859cfd955053c23245c536e4733480239d14bebf12688e35"
        tlp = "CLEAR"
        severity = "high"
    strings:
        $marker      = "Miasma: The Spreading Blight" ascii wide
        $token_nuke  = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner" ascii wide nocase
        $c2_search   = "search/commits?q=firedalazer" ascii wide
        $c2_anthro   = "api.anthropic.com/v1/api" ascii wide nocase
        $aeskey1     = "fe0d71d57ecf4fa0a433185bf59a03f5" ascii nocase
        $aeskey2     = "f5e5dca9b725ec18514c4b322ed35d2b" ascii nocase
        $oidc_env    = "OIDC_PACKAGES" ascii
        $bun_pin     = "oven-sh/bun/releases/download/bun-v1.3.13" ascii nocase
        $edr1        = "StepSecurity Harden-Runner" ascii
        $antianalysis = "TESTING_TAR_FAKE_PLATFORM" ascii
    condition:
        any of ($marker, $token_nuke, $c2_search, $c2_anthro)
        or any of ($aeskey1, $aeskey2)
        or (($oidc_env and $bun_pin) and ($edr1 or $antianalysis))
}
