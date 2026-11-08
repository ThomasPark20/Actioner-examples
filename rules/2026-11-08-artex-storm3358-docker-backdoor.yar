rule ARTEX_Backdoored_Docker_Login_Handler
{
    meta:
        description = "Detects the backdoored ARTEX Docker image login handler containing the verifyCaptcha() function that provides unauthenticated root shell access"
        author = "Actioner"
        date = "2026-11-08"
        reference = "https://thehackernews.com/2026/11/backdoored-docker-image-for-artex-ai.html"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $func = "verifyCaptcha" ascii wide
        $docker1 = "tomicdd/artex" ascii wide
        $docker2 = "congdonglinux/artex" ascii wide
        $docker3 = "mianhuatang11/artex" ascii wide
        $docker4 = "andy1099zz/artex" ascii wide
        $docker5 = "dgddw/artex" ascii wide
        $docker6 = "ylh440104/artex" ascii wide

    condition:
        $func or any of ($docker*)
}
