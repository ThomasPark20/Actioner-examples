/*
 * TeamPCP Supply Chain Attack - YARA Detection Rules
 * Generated: 2026-06-21 | Actioner CTI
 *
 * Sources:
 *   - https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/
 *   - https://ramimac.me/teampcp/
 *   - https://phoenix.security/teampcp-github-breach-durabletask-pypi-supply-chain-wave-four-2026/
 *   - https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions
 */

rule TeamPCP_MiniShaiHulud_Dropper
{
    meta:
        description = "Detects TeamPCP Mini Shai-Hulud dropper payloads based on known C2 domains, file artifacts, and behavioral strings"
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/"
        reference_phoenix = "https://phoenix.security/teampcp-github-breach-durabletask-pypi-supply-chain-wave-four-2026/"
        hash1 = "3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf"
        hash2 = "85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f"

    strings:
        $c2_1 = "check.git-service.com" ascii wide
        $c2_2 = "t.m-kosche.com" ascii wide
        $c2_3 = "scan.aquasecurtiy.org" ascii wide
        $c2_4 = "models.litellm.cloud" ascii wide
        $c2_5 = "checkmarx.zone" ascii wide
        $c2_6 = "git-tanstack.com" ascii wide

        $payload_1 = "rope.pyz" ascii wide
        $payload_2 = "managed.pyz" ascii wide
        $payload_3 = "tpcp.tar.gz" ascii wide
        $payload_4 = "kamikaze.sh" ascii wide

        $artifact_1 = "session.key" ascii
        $artifact_2 = "payload.enc" ascii
        $artifact_3 = "pgmonitor.py" ascii
        $artifact_4 = "gh-token-monitor" ascii

        $dead_drop = "FIRESCALE" ascii wide

        $prop_1 = "start_new_session=True" ascii
        $prop_2 = "/tmp/managed.pyz" ascii

        $exfil_repo_1 = "BABA-YAGA" ascii
        $exfil_repo_2 = "KOSCHEI" ascii
        $exfil_repo_3 = "FIREBIRD" ascii
        $exfil_repo_4 = "RUSALKA" ascii

    condition:
        filesize < 10MB and (
            any of ($c2_*) or
            (any of ($payload_*) and any of ($artifact_*)) or
            ($dead_drop and any of ($prop_*)) or
            (2 of ($exfil_repo_*))
        )
}

rule TeamPCP_DurableTask_PyPI_Dropper
{
    meta:
        description = "Detects the TeamPCP durabletask PyPI dropper payload that downloads rope.pyz from attacker C2"
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://phoenix.security/teampcp-github-breach-durabletask-pypi-supply-chain-wave-four-2026/"
        hash1 = "3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf"

    strings:
        $download = "check.git-service.com" ascii
        $file = "/tmp/managed.pyz" ascii
        $detach = "start_new_session" ascii

    condition:
        uint32(0) != 0x464C457F and
        $download and $file and $detach
}

rule TeamPCP_WAV_Steganography
{
    meta:
        description = "Detects WAV files potentially containing TeamPCP steganographic payloads used in the Telnyx variant"
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/"

    strings:
        $wav_header = { 52 49 46 46 ?? ?? ?? ?? 57 41 56 45 }
        $marker_1 = "session.key" ascii
        $marker_2 = "aes-256-cbc" ascii
        $marker_3 = "payload.enc" ascii

    condition:
        $wav_header at 0 and 2 of ($marker_*)
}

rule TeamPCP_Credential_Harvester_Script
{
    meta:
        description = "Detects Python credential harvesting scripts associated with TeamPCP supply chain attacks. Confidence is low without a TeamPCP-specific C2 domain or function name co-occurring; treat matches as behavioral leads requiring manual triage."
        author = "Actioner CTI"
        date = "2026-06-21"
        reference = "https://ramimac.me/teampcp/"

    strings:
        $cred_1 = ".aws/credentials" ascii
        $cred_2 = ".kube/config" ascii
        $cred_3 = ".npmrc" ascii
        $cred_4 = ".docker/config.json" ascii
        $cred_5 = ".ssh/id_rsa" ascii

        $api_1 = "/latest/meta-data/iam/security-credentials" ascii
        $api_2 = "/api/v1/namespaces" ascii
        $api_3 = "/api/v1/secrets" ascii

        $exfil_1 = "base64.b64decode" ascii
        $exfil_2 = "openssl" ascii

        $teampcp_1 = "check.git-service.com" ascii
        $teampcp_2 = "t.m-kosche.com" ascii
        $teampcp_3 = "scan.aquasecurtiy.org" ascii
        $teampcp_4 = "tpcp.tar.gz" ascii
        $teampcp_5 = "pgmonitor" ascii

    condition:
        filesize < 500KB and
        3 of ($cred_*) and
        any of ($api_*) and
        any of ($exfil_*) and
        any of ($teampcp_*)
}
