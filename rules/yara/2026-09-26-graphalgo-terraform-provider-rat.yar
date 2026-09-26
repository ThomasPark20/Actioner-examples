rule graphalgo_terraform_provider_malware
{
    meta:
        description = "Detects Graphalgo malicious Terraform provider Go RAT by embedded strings: activation hash, C2 contract address, threat actor public key, Slack workspace names, and encrypted payload filenames."
        author = "Actioner"
        date = "2026-09-26"
        reference = "https://www.aikido.dev/blog/graphalgo-terraform-go-modules"
        hash_payload_terraform = "5f892a5424e88a21a3eb3d7f82ebf04d8ac31cdb19ada25153be4165df977d0f"
        hash_payload_gomod = "ab01686d87565250fc4989faddb877d793667b07ec217a61cbd798f5695d62f5"

    strings:
        $trigger = "b9966e3762e9a0d5d263b8cb3cca07294f81af9714d40ddf4628cb85d74e8ad5" ascii nocase
        $contract = "0xAD02b5cDE693529d3bdA0266299501ad0193036C" ascii nocase
        $pubkey = "302a300506032b656e032100bad013df6eec5d686f4cc8551e0a5c87a0135164bdd1dafb1c75141d1b526702" ascii nocase
        $slack1 = "portfolio-devs.slack.com" ascii nocase
        $slack2 = "portfolio-testers.slack.com" ascii nocase
        $sqlite_payload = "import-resource.sqlite3" ascii
        $gomod1 = "gocommunity.io/orderedbtree" ascii
        $gomod2 = "gogets.dev/btreex" ascii
        $filepath = "resource_docker_container_funcs.go" ascii
        $marker = "68656c6c6f6970626f742121" ascii nocase

    condition:
        filesize < 50MB and
        (uint32(0) == 0x464c457f or
        uint16(0) == 0x5a4d or
        uint32(0) == 0xfeedface or
        uint32(0) == 0xfeedfacf) and
        3 of them
}
