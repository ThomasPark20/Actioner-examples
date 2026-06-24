// YARA rules for CVE-2026-8461 (PixelSmash) - FFmpeg MagicYUV heap OOB write
// Source: /home/user/Actioner-examples/summaries/2026-06-23-ffmpeg-pixelsmash-rce.md
// revision: v2 - AVI rule: removed $coded_height_32 (ubiquitous 4-byte pattern),
//   downgraded to low; MKV rule: removed V_MS/VFW/FOURCC (too broad), require
//   MAGY FourCC, downgraded to low; Generic rule: unchanged (PASS)

rule Exploit_CVE_2026_8461_PixelSmash_MagicYUV_AVI
{
    meta:
        description = "Detects crafted AVI files exploiting CVE-2026-8461 PixelSmash via MagicYUV codec - small AVI with MAGY FourCC. Broad heuristic: any small AVI carrying MagicYUV will match."
        author = "Actioner"
        date = "2026-06-23"
        modified = "2026-06-23"
        reference = "https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/"
        severity = "low"
        tlp = "WHITE"

    strings:
        // AVI RIFF header
        $avi_riff = { 52 49 46 46 [4] 41 56 49 20 }

        // MagicYUV FourCC in AVI stream header (strf/strh)
        $magy_fourcc = "MAGY" ascii

        // MagicYUV codec identifier variants
        $magy_lower = "magy" ascii

    condition:
        $avi_riff at 0 and
        ($magy_fourcc or $magy_lower) and
        filesize < 200KB
}

rule Exploit_CVE_2026_8461_PixelSmash_MagicYUV_MKV
{
    meta:
        description = "Detects crafted MKV files with MagicYUV codec presence and small file size. Broad codec-presence heuristic: V_MS/VFW/FOURCC matches any VFW-wrapped codec in MKV, not just MagicYUV. Conjunction with MAGY FourCC or small size provides modest specificity."
        author = "Actioner"
        date = "2026-06-23"
        modified = "2026-06-23"
        reference = "https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/"
        severity = "low"
        tlp = "WHITE"

    strings:
        // EBML/MKV magic bytes
        $mkv_magic = { 1A 45 DF A3 }

        // MagicYUV FourCC - required for specificity
        $magy_fourcc = "MAGY" ascii

        // MagicYUV codec private data marker
        $magy_lower = "magy" ascii

    condition:
        $mkv_magic at 0 and
        ($magy_fourcc or $magy_lower) and
        filesize < 200KB
}

rule Exploit_CVE_2026_8461_PixelSmash_MagicYUV_Generic
{
    meta:
        description = "Detects media files containing MagicYUV codec data with embedded shell command strings, indicating a weaponized CVE-2026-8461 PixelSmash exploit payload"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/"
        severity = "high"
        tlp = "WHITE"

    strings:
        // MagicYUV FourCC
        $magy = "MAGY" ascii

        // Common shell command fragments that may appear in exploit payload
        $cmd1 = "/bin/sh" ascii
        $cmd2 = "/bin/bash" ascii
        $cmd3 = "system(" ascii
        $cmd4 = "cmd.exe" ascii wide
        $cmd5 = "powershell" ascii nocase

    condition:
        $magy and
        1 of ($cmd*) and
        filesize < 500KB
}
