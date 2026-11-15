rule Falcon_C2_Browser_Extension_Manifest
{
    meta:
        description = "Detects Falcon C2 malicious browser extension manifest disguised as PDF Viewer"
        author = "Actioner"
        date = "2026-11-15"
        reference = "https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/"
        hash = "b6a7be724871ed3e81c986b74d62da8911c82a336c4c1857b35f2446b2d49fda"

    strings:
        $ext_name = "PDF Viewer" ascii wide
        $ext_desc = "Portable Document Format" ascii wide
        $ext_version = "2026.5.13.1" ascii wide
        $ext_id = "mbidcmlcbgbphpoacojjbmfpohcimjji" ascii wide
        $file_analytics = "analytics-core.js" ascii wide
        $file_twitter = "twitter-dm.js" ascii wide
        $file_sandbox = "sandbox.html" ascii wide
        $file_offscreen = "offscreen.js" ascii wide
        $all_urls = "<all_urls>" ascii wide

    condition:
        ($ext_id) or
        ($ext_name and $ext_desc and $ext_version) or
        ($ext_name and $all_urls and 3 of ($file_*))
}
