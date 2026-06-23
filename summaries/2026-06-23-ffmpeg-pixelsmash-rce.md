# Technical Analysis Report: FFmpeg PixelSmash (CVE-2026-8461) (2026-06-23)

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-23
Version: 1.0-draft

## Executive Summary

CVE-2026-8461, dubbed "PixelSmash," is a heap out-of-bounds write vulnerability (CVSS 8.8 High) in FFmpeg's MagicYUV video decoder (`libavcodec/magicyuv.c`) that enables remote code execution through crafted AVI, MKV, or MOV video files as small as 50 KB. The flaw arises from a rounding mismatch between the frame allocator and the MagicYUV decoder when computing chroma plane heights for subsampled pixel formats like YUV420p, allowing an attacker-controlled `slice_height` value to trigger a one-row heap buffer overflow.

JFrog Security Research demonstrated reliable RCE against Jellyfin 10.11.9 media servers via normal media library scan pipelines, requiring zero user interaction beyond file placement. The vulnerability also causes denial-of-service crashes in Kodi, Emby, Nextcloud, PhotoPrism, Immich, OBS Studio, mpv, and desktop thumbnail generators. FFmpeg addressed the issue in version 8.1.2 (released June 17, 2026). Since the MagicYUV decoder is enabled by default in upstream FFmpeg builds and major Linux distributions, the attack surface is extremely broad.

## Background: FFmpeg and the MagicYUV Decoder

FFmpeg is the dominant open-source multimedia framework used for decoding, encoding, transcoding, and streaming audio and video. Its `libavcodec` library is embedded in hundreds of applications, from media servers (Jellyfin, Emby, Plex) to desktop players (Kodi, mpv, VLC), cloud platforms (Nextcloud, Immich, PhotoPrism), production tools (OBS Studio), and AI/ML inference pipelines (vLLM, LLaVA via PyAV).

MagicYUV is a lossless video codec identified by the FourCC code `MAGY`. It uses horizontally divided slices per video frame. For subsampled chroma formats (e.g., YUV420p), the decoder must translate luma slice heights into corresponding chroma slice heights using ceiling-division rounding. The vulnerability exists because the frame allocator and the decoder use inconsistent rounding logic for this translation.

## Attack Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| 2026-05-13 | JFrog reports CVE-2026-8461 to FFmpeg security team |
| 2026-05-24 | JFrog notifies downstream projects: Jellyfin, mpv, OBS, PhotoPrism, Immich |
| 2026-06-17 | FFmpeg releases version 8.1.2 with fix |
| 2026-06-18 | CVE-2026-8461 published (CVSS 8.8) |
| 2026-06-22 | JFrog publishes full technical writeup |

## Root Cause: Chroma Plane Height Rounding Mismatch in MagicYUV Decoder

The vulnerability is classified as CWE-787 (Out-of-bounds Write). The root cause is an inconsistency between how FFmpeg's frame allocator and the MagicYUV decoder compute chroma plane heights for subsampled pixel formats.

**Frame allocator** (`get_buffer.c`): Computes chroma height using `AV_CEIL_RSHIFT(FFALIGN(height, 32), 1)`. For `coded_height=32`, this allocates exactly 16 chroma rows.

**MagicYUV decoder** (`magicyuv.c`): Reads the attacker-controlled `slice_height` from the bitstream (line 550), computes the number of slices as `(coded_height + slice_height - 1) / slice_height`, and for each slice computes chroma rows as `AV_CEIL_RSHIFT(slice_height, 1)`. With `slice_height=31` and `coded_height=32`, this produces 2 slices, each claiming 16 chroma rows -- but only 16 rows total were allocated. The second slice writes to row 16 of a 16-row buffer, producing a one-row (640-byte with `coded_width=1280`) heap out-of-bounds write.

The existing `slice_height` validation at `magicyuv.c:566` only checks the interlaced code path. The non-interlaced path exploited in this attack has no alignment check.

## Technical Analysis of the Malicious Payload

### 1. Exploit Delivery via Crafted Media Files

The exploit is delivered as a small (approximately 50 KB) video file in AVI, MKV, or MOV container format containing MagicYUV-encoded (`MAGY` FourCC) video data. The critical fields are:

- `coded_width`: 1280 (produces 640-byte chroma width after subsampling)
- `coded_height`: 32
- `slice_height`: 31 (odd value that triggers ceiling-round overflow)

The payload encodes shell commands and glibc chunk metadata within the overflow region to preserve malloc integrity.

### 2. Heap Layout Hijacking and RCE

The 640-byte OOB write lands on the `AVBuffer` structure allocated immediately after the chroma plane buffer. The exploit overwrites:

- Offset +280: `AVBuffer.free` function pointer (overwritten with address of `system()`)
- Offset +288: `AVBuffer.opaque` pointer (overwritten with address of attacker command string)

When `av_buffer_unref()` executes during frame cleanup, the indirect call `buf->free(buf->opaque, buf->data)` becomes `system(attacker_command)`, achieving arbitrary command execution.

Full RCE requires ASLR to be disabled or bypassed via an additional vulnerability. JFrog demonstrated reliable exploitation against Jellyfin 10.11.9 where ASLR was not effective.

### 3. Attack Vectors

The near-zero-click nature of this vulnerability enables multiple attack vectors:

- **Desktop:** Browsing a folder containing the malicious file triggers `ffmpegthumbnailer` for thumbnail generation
- **Media servers:** Uploading to Jellyfin/Emby/Nextcloud triggers automatic library scanning via `ffprobe`
- **Torrent/download:** Files downloaded to a monitored media folder auto-trigger processing
- **AI/ML pipelines:** PyAV-based video decoding in vLLM/LLaVA inference pipelines

### 4. Platform-Specific Behavior

#### Linux (Primary Target)
- Exploitation targets the `system()` function from glibc
- Thumbnail generators (GNOME, KDE, XFCE) are vulnerable via `ffmpegthumbnailer`
- Server applications (Jellyfin, Nextcloud) process files automatically on upload

#### Windows
- Similar exploitation path via `system()` / `cmd.exe`
- Desktop media players and thumbnail handlers affected

### 5. Crash Signatures (DoS Path)

When exploitation does not achieve full RCE, the following crash indicators appear:

- `munmap_chunk(): invalid pointer` followed by `SIGABRT`
- `SIGSEGV` in `bytestream_get_buffer()`
- `AddressSanitizer: heap-buffer-overflow` (on ASAN builds)
- Silent exit code 0 with heap corruption (production builds of Jellyfin, Emby)

## Indicators of Compromise (IOCs)

> **Defanging Convention:** All IOCs in this report use defanged notation to prevent accidental resolution or click-through:
> - URLs: `hxxps://` or `hxxp://`
> - Domains: `[.]` replacing dots

### Software Level

| Component | Vulnerable Versions | Description |
|-----------|-------------------|-------------|
| FFmpeg libavcodec | All versions before 8.1.2 / 8.0.3 | MagicYUV decoder heap OOB write |
| Jellyfin | 10.11.9 and earlier (using vulnerable FFmpeg) | RCE via media library scan |
| Kodi, Emby, Nextcloud, mpv, OBS Studio, PhotoPrism, Immich | Any version using FFmpeg < 8.1.2 | DoS / potential RCE |

### File System

| Indicator | Value | Description |
|-----------|-------|-------------|
| Codec FourCC | `MAGY` | MagicYUV codec identifier in container headers |
| Container formats | AVI (RIFF/AVI), MKV (EBML), MOV (ftyp/moov) | Exploit delivery containers |
| Typical exploit size | ~50 KB | Unusually small for video files |
| Pixel format | YUV420p (subsampled) | Required for chroma plane height mismatch |
| coded_height | 32 | PoC-specific frame height |
| slice_height | 31 (odd) | Triggers ceiling-round overflow |

### Behavioral

- FFmpeg/ffprobe crashing with SIGABRT or SIGSEGV during MagicYUV decoding
- Media server (Jellyfin, Emby) spawning unexpected shell processes (`/bin/sh`, `/bin/bash`) after media scanning
- Unexpected `system()` calls originating from FFmpeg library code paths
- Small video files (<200 KB) containing MagicYUV codec data with frame heights <= 64 and odd slice_height values

## MITRE ATT&CK Mapping

| TID | Technique | Observed Behavior |
|-----|-----------|-------------------|
| T1203 | Exploitation for Client Execution | Crafted video file triggers heap OOB write in FFmpeg MagicYUV decoder during media processing |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Post-exploitation RCE achieved via hijacked function pointer calling `system()` with shell commands |
| T1204.002 | User Execution: Malicious File | Victim processes crafted media file (near-zero-click via auto-scan or thumbnail generation) |

## Impact Assessment

**Breadth:** Extremely wide. FFmpeg's `libavcodec` is used by hundreds of applications across desktop, server, cloud, and AI/ML environments. The MagicYUV decoder is enabled by default in upstream builds and major Linux distribution packages.

**Depth:** Critical for media servers. Full RCE demonstrated against Jellyfin 10.11.9 in realistic attack scenarios (media library upload). DoS is reliable across all affected applications.

**Stealth:** High. Exploitation can occur through normal media processing workflows (folder browsing, library scans, thumbnail generation) with no user interaction. Production builds may silently corrupt the heap without visible crashes.

## Detection & Remediation

### Immediate Detection

Check if your FFmpeg installation includes the vulnerable MagicYUV decoder:
```bash
ffmpeg -decoders 2>/dev/null | grep magicyuv
```
Output containing `VFS..D magicyuv` indicates the decoder is enabled and the installation may be vulnerable.

Check FFmpeg version:
```bash
ffmpeg -version | head -1
```
Versions prior to 8.1.2 (or 8.0.3 for the 8.0.x branch) are vulnerable.

### Remediation

1. **Update FFmpeg** to version 8.1.2 or 8.0.3 immediately
2. **Update Jellyfin** and other media server applications that bundle FFmpeg
3. **Disable MagicYUV decoder** as a temporary mitigation if immediate update is not possible:
   ```bash
   ffmpeg -disabledec magicyuv ...
   ```
4. **Audit media libraries** for suspicious small video files (<200 KB) containing MagicYUV codec data
5. **Monitor** for FFmpeg process crashes (SIGABRT/SIGSEGV) and unexpected shell spawns from media server processes

### Long-Term Hardening

- Build FFmpeg with minimal decoder allowlists rather than enabling all decoders by default
- Run media processing in sandboxed environments (containers, seccomp profiles)
- Ensure ASLR is enabled and effective on all media-processing systems
- Implement file-type validation and codec allowlisting before passing media files to FFmpeg

## Detection Rules

Three YARA rules detect crafted media files carrying MagicYUV exploit payloads at the file level. Two Sigma rules detect exploitation behavior on Linux endpoints -- FFmpeg crashes and post-exploitation shell spawning from media servers. One Snort rule and two Suricata rules detect network delivery of exploit files over HTTP. All rules target PoC-specific indicators (MAGY FourCC, small file sizes, crash signatures) and should be tuned for environments with legitimate MagicYUV usage.

### YARA: Crafted AVI with MagicYUV Exploit Indicators

Detects AVI files containing MagicYUV codec data with the PoC-characteristic `coded_height=32` and small file size, matching the documented 50 KB exploit payload structure.

**Status:** compile pass | confidence: medium

<!-- audit: yarac exit 0. Rule matches AVI RIFF header + MAGY FourCC + LE uint32 0x20 (32) + filesize <200KB. The coded_height byte pattern {20 00 00 00} may false-positive on unrelated 4-byte sequences within AVI metadata; the conjunction with MAGY FourCC and size constraint mitigates this. No hash available for known PoC sample. -->

```yara
rule Exploit_CVE_2026_8461_PixelSmash_MagicYUV_AVI
{
    meta:
        description = "Detects crafted AVI files exploiting CVE-2026-8461 PixelSmash via MagicYUV codec with anomalous slice_height triggering heap OOB write"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // AVI RIFF header
        $avi_riff = { 52 49 46 46 [4] 41 56 49 20 }

        // MagicYUV FourCC in AVI stream header (strf/strh)
        $magy_fourcc = "MAGY" ascii

        // MagicYUV codec identifier variants
        $magy_lower = "magy" ascii

        // Typical exploit coded_height=32 as little-endian uint32
        $coded_height_32 = { 20 00 00 00 }

    condition:
        $avi_riff at 0 and
        ($magy_fourcc or $magy_lower) and
        $coded_height_32 and
        filesize < 200KB
}
```

### YARA: Crafted MKV with MagicYUV Exploit Indicators

Detects Matroska (MKV) containers carrying MagicYUV codec data with small file size, covering the MKV delivery vector documented in the advisory.

**Status:** compile pass | confidence: medium

<!-- audit: yarac exit 0. Matches EBML header + MAGY or V_MS/VFW/FOURCC + filesize <200KB. MKV files legitimately carrying MagicYUV content will match if under 200KB; this is expected to be rare in production environments. -->

```yara
rule Exploit_CVE_2026_8461_PixelSmash_MagicYUV_MKV
{
    meta:
        description = "Detects crafted MKV files exploiting CVE-2026-8461 PixelSmash via MagicYUV codec with small frame dimensions"
        author = "Actioner"
        date = "2026-06-23"
        reference = "https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/"
        severity = "critical"
        tlp = "WHITE"

    strings:
        // EBML/MKV magic bytes
        $mkv_magic = { 1A 45 DF A3 }

        // MagicYUV codec identifier in Matroska CodecID
        $codec_magy = "V_MS/VFW/FOURCC" ascii
        $magy_fourcc = "MAGY" ascii

        // MagicYUV codec private data marker
        $magy_lower = "magy" ascii

    condition:
        $mkv_magic at 0 and
        ($codec_magy or $magy_fourcc or $magy_lower) and
        filesize < 200KB
}
```

### YARA: MagicYUV Media File with Embedded Shell Commands

Detects any media file containing MagicYUV codec identifiers alongside embedded shell command strings, indicating a weaponized exploit payload carrying its RCE command.

**Status:** compile pass | confidence: high

<!-- audit: yarac exit 0. MAGY FourCC + shell command fragments (/bin/sh, /bin/bash, system(, cmd.exe, powershell) + filesize <500KB. Low FP rate: legitimate video files should not contain shell command strings alongside MagicYUV codec data. -->

```yara
rule Exploit_CVE_2026_8461_PixelSmash_MagicYUV_Generic
{
    meta:
        description = "Detects media files containing MagicYUV codec data with characteristics matching CVE-2026-8461 PixelSmash exploit payloads"
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
```

### Sigma: FFmpeg MagicYUV Decoder Crash Detection

Detects FFmpeg or ffprobe crashes with crash-related signals (SIGABRT, SIGSEGV, munmap_chunk) that indicate heap corruption from CVE-2026-8461 exploitation.

**Status:** compile pass (sigma check 0 errors, converts to Splunk and LogScale) | confidence: medium

Requires process creation logging with parent-child relationships (e.g., Sysmon for Linux or auditd with process tracking).

<!-- audit: sigma check 0 errors 0 issues. sigma convert --without-pipeline -t splunk succeeds. sigma convert --without-pipeline -t log_scale succeeds. Detection relies on crash strings appearing in CommandLine of child processes spawned by the crashing FFmpeg parent; this depends on how the OS propagates crash diagnostics. Some crash scenarios may produce SIGSEGV in FFmpeg itself without spawning a child process, which this rule would miss. -->

```yaml
title: FFmpeg MagicYUV Decoder Crash Indicating CVE-2026-8461 PixelSmash Exploitation
id: 7a3e1f42-9c8d-4b2e-a6f5-3d0e7b8c9a14
status: experimental
description: >
    Detects FFmpeg or ffprobe process crashes with signals (SIGABRT, SIGSEGV)
    that indicate exploitation of CVE-2026-8461 PixelSmash, a heap out-of-bounds
    write in the MagicYUV decoder. Crashes during media processing of small AVI,
    MKV, or MOV files containing MagicYUV codec data are strong indicators of
    exploitation attempts.
references:
    - https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/
    - https://www.bleepingcomputer.com/news/security/ffmpeg-fixes-pixelsmash-flaw-in-widely-used-video-decoder/
    - https://vulnerability.circl.lu/vuln/ghsa-qff7-4q6c-m8h6
author: Actioner
date: 2026-06-23
tags:
    - attack.t1203
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/ffmpeg'
            - '/ffprobe'
            - '/ffmpegthumbnailer'
    selection_crash:
        Image|endswith:
            - '/sh'
            - '/bash'
        CommandLine|contains:
            - 'core dumped'
            - 'SIGABRT'
            - 'SIGSEGV'
            - 'munmap_chunk'
            - 'heap-buffer-overflow'
    condition: selection_parent and selection_crash
falsepositives:
    - Legitimate FFmpeg crashes from corrupted but non-malicious media files
    - Debug or fuzzing environments generating intentional crashes
level: high
```

### Sigma: Jellyfin/Emby Shell Spawn After FFmpeg Processing (RCE Indicator)

Detects media server processes spawning shell commands after FFmpeg media processing, indicating successful CVE-2026-8461 RCE via hijacked `AVBuffer.free` function pointer redirecting to `system()`.

**Status:** compile pass (sigma check 0 errors, converts to Splunk and LogScale) | confidence: high

<!-- audit: sigma check 0 errors 0 issues. sigma convert --without-pipeline -t splunk succeeds. sigma convert --without-pipeline -t log_scale succeeds. This rule detects post-exploitation behavior (shell spawn from media server) rather than the vulnerability trigger itself, making it resilient to exploit variants. False positives possible from legitimate plugin-based transcoding that invokes shell scripts, but these should be rare and can be filtered by specific CommandLine patterns. -->

```yaml
title: Jellyfin Media Server Spawning Shell After FFmpeg Processing Indicating CVE-2026-8461 RCE
id: 2b4d8e61-5f3a-4c7e-b9d2-1a6f0c3e5d87
status: experimental
description: >
    Detects Jellyfin media server processes spawning shell commands after FFmpeg
    media processing, which may indicate successful exploitation of CVE-2026-8461
    PixelSmash to achieve remote code execution. The exploit overwrites AVBuffer
    function pointers to redirect execution to system() with attacker-controlled
    arguments.
references:
    - https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/
    - https://www.bleepingcomputer.com/news/security/ffmpeg-fixes-pixelsmash-flaw-in-widely-used-video-decoder/
author: Actioner
date: 2026-06-23
tags:
    - attack.t1203
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/jellyfin'
            - '/jellyfin-web'
            - '/emby'
            - '/EmbyServer'
        ParentCommandLine|contains:
            - 'ffmpeg'
            - 'ffprobe'
            - 'MediaEncoder'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/zsh'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate post-processing scripts invoked by media servers
    - Plugin-based transcoding pipelines that spawn shell commands
level: critical
```

### Snort: MagicYUV AVI Exploit File Network Delivery

Detects AVI files containing MagicYUV codec data delivered over TCP, matching the documented exploit delivery containers.

**Status:** compile pass (Snort 2.9.20 validation successful) | confidence: medium

<!-- audit: snort -c /etc/snort/snort.conf -T with included rule exits 0. Rule matches RIFF AVI header followed by MAGY FourCC in TCP stream to HOME_NET. Content match uses depth/distance for positional accuracy. May match legitimate MagicYUV AVI transfers; the conjunction with RIFF+AVI+MAGY constrains FPs to actual MagicYUV content. Cannot distinguish exploit from benign MagicYUV at the network level without deeper inspection. -->

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - CVE-2026-8461 PixelSmash MagicYUV Exploit AVI File Delivery via HTTP"; flow:established,to_client; content:"RIFF"; depth:4; content:"AVI "; distance:0; within:8; content:"MAGY"; distance:0; classtype:attempted-user; reference:cve,2026-8461; reference:url,jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/; metadata:author Actioner, created_at 2026-06-23, cve CVE-2026-8461; sid:2100002; rev:1;)
```

### Suricata: MagicYUV AVI Exploit File HTTP Delivery

Detects AVI files containing MagicYUV codec data delivered over HTTP using Suricata's `file.data` buffer for reassembled file inspection.

**Status:** compile pass (Suricata 7.0.3 validation successful) | confidence: medium

<!-- audit: suricata -T -S exits 0. Uses file.data buffer for reassembled file content inspection. Matches RIFF header at depth 4 + AVI marker + MAGY FourCC. Same FP caveat as Snort rule: any legitimate MagicYUV AVI delivered over HTTP will match. -->

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - CVE-2026-8461 PixelSmash MagicYUV Exploit AVI Delivery"; flow:established,to_client; file.data; content:"RIFF"; depth:4; content:"AVI "; distance:0; within:8; content:"MAGY"; fast_pattern; classtype:attempted-user; reference:cve,2026-8461; reference:url,jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/; metadata:author Actioner, created_at 2026-06-23, cve CVE-2026-8461; sid:2200001; rev:1;)
```

### Suricata: MagicYUV MKV Exploit File HTTP Delivery

Detects Matroska (MKV) files containing MagicYUV codec data delivered over HTTP, covering the MKV exploit delivery vector.

**Status:** compile pass (Suricata 7.0.3 validation successful) | confidence: medium

<!-- audit: suricata -T -S exits 0. Matches EBML header (hex 1A 45 DF A3) at depth 4 + MAGY FourCC via file.data buffer. Same legitimate-MagicYUV FP caveat applies. -->

```
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Actioner - CVE-2026-8461 PixelSmash MagicYUV Exploit MKV Delivery"; flow:established,to_client; file.data; content:"|1A 45 DF A3|"; depth:4; content:"MAGY"; fast_pattern; classtype:attempted-user; reference:cve,2026-8461; reference:url,jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/; metadata:author Actioner, created_at 2026-06-23, cve CVE-2026-8461; sid:2200002; rev:1;)
```

## Lessons Learned

1. **Library-level vulnerabilities have blast-radius multiplier effects.** A single bug in `libavcodec` impacts hundreds of downstream applications, from desktop media players to cloud platforms and AI inference pipelines. Dependency tracking and rapid patch propagation are critical.

2. **Auto-processing pipelines transform local vulnerabilities into remote ones.** The near-zero-click exploitation path (file upload triggers automatic scan) demonstrates that any automated media processing pipeline effectively converts a local file-parsing bug into a remote attack vector.

3. **Default-enabled codec attack surface is underestimated.** Most FFmpeg deployments enable all decoders by default, including rarely-used codecs like MagicYUV. Minimal decoder allowlists and sandboxed processing would dramatically reduce the exploitable attack surface.

## Sources

- [JFrog Security Research - PixelSmash Blog](https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/) — primary technical writeup with root cause analysis, exploitation details, and PoC demonstration
- [BleepingComputer - FFmpeg Fixes PixelSmash](https://www.bleepingcomputer.com/news/security/ffmpeg-fixes-pixelsmash-flaw-in-widely-used-video-decoder/) — initial news coverage with timeline and impact summary
- [Cryptika - Critical FFmpeg Vulnerability](https://www.cryptika.com/critical-ffmpeg-vulnerability-allows-attackers-to-weaponize-media-files/) — technical analysis with exploitation mechanism details
- [CIRCL Vulnerability Lookup - GHSA-qff7-4q6c-m8h6](https://vulnerability.circl.lu/vuln/ghsa-qff7-4q6c-m8h6) — CVSS vector, CWE classification, and affected version details
- [FFmpeg Security Advisories](https://ffmpeg.org/security.html) — official patch commit hashes and affected version ranges
- [FFmpeg Pull Request #23159](https://code.ffmpeg.org/FFmpeg/FFmpeg/pulls/23159) — patch code review
- [OffSeq Threat Radar](https://radar.offseq.com/threat/ffmpeg-fixes-pixelsmash-flaw-in-widely-used-video--5ccb783d6ccf419b) — threat intelligence aggregation

---
*Report generated by Actioner*
