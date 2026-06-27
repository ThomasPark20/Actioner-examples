# Polymarket Supply Chain Attack --- Crypto Theft via Compromised Frontend Vendor

Prepared by: Actioner
Classification: TLP:WHITE
Date: 2026-06-27
Version: 1.0 (DRAFT)

## Executive Summary

On June 25, 2026, attackers compromised an unnamed third-party vendor that supplied frontend code to Polymarket, the largest decentralized prediction market platform. The attackers injected malicious JavaScript into the Polymarket web frontend, which tricked users into signing fraudulent wallet approval transactions. The attack drained approximately $2.94 million in PUSD (Polymarket's USDC-backed stablecoin on the Polygon network) from at least 11 victim wallets. Stolen funds were bridged from Polygon to Ethereum and swapped into approximately 1,893 ETH, consolidated into attacker-controlled wallet `0xe65b1C586757c5510B60F998Eebb14C1eF71E1eD`. Polymarket contained the breach within 15 minutes of public disclosure by security researcher Specter, removed the compromised dependency, and committed to fully refunding all affected users.

**Viability Gate: No production-ready detection rules --- insufficient technical artifacts.** Polymarket has not disclosed the compromised vendor identity, the malicious JavaScript payload, C2 domains, or network-level indicators. The only concrete IOCs available are blockchain wallet addresses, which are not actionable for traditional network or endpoint detection. This report documents the incident for situational awareness and provides behavioral detection guidance.

## Background

Polymarket is a decentralized prediction market platform operating on the Polygon blockchain. Users deposit USDC, which is represented as PUSD (Polymarket USD) within the platform, and use it to trade on prediction market outcomes. Users interact with the platform through a web frontend that connects to their cryptocurrency wallets (e.g., MetaMask) via standard Web3 interfaces.

This incident marks Polymarket's second security breach in two months. In May 2026, a separate incident involving a compromised six-year-old private key tied to an internal operations wallet resulted in approximately $520,000 drained from two smart contracts on the Polygon network. Additionally, earlier in 2026 (February and April), npm-based supply chain attacks targeted Polymarket developers specifically, involving malicious packages designed to steal API credentials and private keys --- though those were distinct campaigns.

The June 2026 frontend attack was recorded by DefiLlama as the 89th crypto security breach in Q2 2026, contributing to the highest quarterly incident count in DeFi history.

## Technical Analysis

### Attack Chain

```
[1] Third-Party Vendor Compromise
    |
    v
[2] Malicious JavaScript Injection into Polymarket Frontend
    |
    v
[3] Users Visit Official Polymarket Website (polymarket.com)
    |
    v
[4] Injected Script Activates on Wallet Connection
    |
    v
[5] Fraudulent Transaction Approval Prompts Displayed to Users
    |
    v
[6] Users Unknowingly Sign Token Approval / Transfer Transactions
    |
    v
[7] PUSD Drained from Victim Wallets on Polygon
    |
    v
[8] Funds Bridged from Polygon to Ethereum
    |
    v
[9] PUSD Swapped to ~1,893 ETH
    |
    v
[10] ETH Consolidated into Attacker Wallets
```

### Attack Vector: Supply Chain Frontend Compromise

The attackers compromised an unnamed third-party vendor whose code was integrated into Polymarket's web frontend. This is a classic software supply chain attack (MITRE ATT&CK T1195.002) where the trust relationship between Polymarket and its vendor was exploited. The compromised dependency delivered malicious JavaScript directly to users' browsers when they visited the legitimate Polymarket website.

### Malicious Script Behavior

Based on available reporting, the injected JavaScript:

1. **Activated upon wallet connection** --- The script waited for users to connect their Web3 wallets to the Polymarket interface
2. **Generated fraudulent approval transactions** --- The script prompted users to sign or approve ERC-20 token approval transactions that appeared legitimate but actually granted the attacker unlimited spending allowance over the victim's PUSD holdings
3. **Targeted PUSD specifically** --- Only the platform's primary stablecoin was targeted, not other tokens
4. **Operated selectively** --- The phrase "for some users" in Polymarket's disclosure suggests the malicious script may have been served conditionally (geofencing, timing, user profiling, or random sampling to avoid detection)

**Critical gap**: The actual JavaScript payload, obfuscation techniques, delivery mechanism (inline injection vs. external script load), and triggering conditions have not been publicly disclosed.

### Fund Laundering Chain

1. PUSD drained from 11+ victim wallets on Polygon
2. Funds bridged from Polygon to Ethereum (likely via Polygon PoS Bridge or a third-party cross-chain bridge)
3. Converted to approximately 1,893 ETH
4. Routed through at least four staging wallets before consolidation
5. Consolidated into primary attacker wallet

### Timeline (All Times UTC)

| Timestamp | Event |
|-----------|-------|
| June 25, 2026 (morning) | Polymarket discovers compromised vendor / malicious script |
| June 25, 2026, ~14:28 UTC | Security researcher Specter publicly flags suspicious on-chain activity |
| June 25, 2026, ~14:43 UTC | Polymarket publicly confirms the breach via X (formerly Twitter) |
| June 25, 2026, ~14:50 UTC | PeckShield provides forensic amplification (fund tracing, bridge/swap details) |
| June 25, 2026 | Polymarket removes compromised dependency and contains breach |
| June 25, 2026 | Polymarket commits to full user reimbursement |

Polymarket contained the breach within approximately 15 minutes of the first public report.

## Indicators of Compromise (IOCs)

> **DEFANGED per policy.** All wallet addresses are presented as-is (not defangable). No network-layer IOCs (domains, IPs, URLs) have been publicly disclosed.

### Blockchain Wallet Addresses

| Address | Role | Chain |
|---------|------|-------|
| `0xe65b1C586757c5510B60F998Eebb14C1eF71E1eD` | Primary consolidation wallet | Ethereum |
| `0xC771A30a...` (truncated) | Staging wallet | Polygon / Ethereum |
| `0xC44F2Ca6...` (truncated) | Staging wallet | Polygon / Ethereum |
| `0x10366AdB...` (truncated) | Staging wallet | Polygon / Ethereum |
| `0x7BCECe0d...` (truncated) | Staging wallet | Polygon / Ethereum |

**Note**: Only the primary consolidation address was published in full. The four staging wallet addresses are truncated in all available sources. Full addresses may be obtainable from on-chain analysis of the consolidation wallet's inbound transactions.

### Network/Endpoint IOCs

**None available.** The following have NOT been publicly disclosed:

- Compromised vendor identity or domain
- Malicious JavaScript payload or code patterns
- C2 domains or IP addresses
- Malicious script hosting URLs
- Exfiltration endpoints
- Blockchain transaction hashes

### Behavioral Indicators

- Unexpected ERC-20 `approve()` calls with unlimited allowance (`type(uint256).max`) targeting PUSD contract on Polygon
- Token transfers to previously unseen addresses immediately following approval transactions
- Cross-chain bridge transactions from Polygon to Ethereum following bulk PUSD transfers
- Rapid swap of bridged tokens to ETH on Ethereum DEXs

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Application |
|--------|-----------|----|-------------|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Compromise of third-party frontend vendor |
| Execution | User Execution: Malicious Link | T1204.001 | Users interact with compromised legitimate website |
| Collection | Input Capture | T1056 | Injected script captures wallet interaction/approval |
| Impact | Financial Theft | T1657 | $2.94M PUSD drained from victim wallets |
| Defense Evasion | Obfuscated Files or Information | T1027 | Malicious JavaScript likely obfuscated (assumed) |
| Exfiltration | Exfiltration Over Web Service | T1567 | Stolen funds exfiltrated via blockchain transactions |
| Resource Development | Acquire Infrastructure: Wallet | T1583.xxx | Attacker-controlled crypto wallets for fund collection |

## Detection Rules

### Viability Assessment

**No production-ready detection rules can be generated for this incident.**

The available IOCs consist exclusively of blockchain wallet addresses, which are not suitable for traditional Sigma, YARA, Suricata, or Snort rules because:

1. **No malicious domains or IPs** --- No Suricata/Snort DNS or network traffic rules possible
2. **No malicious JavaScript payload** --- No YARA rules for code pattern matching possible
3. **No endpoint artifacts** --- No Sigma rules for process/file/registry detection possible
4. **Wallet addresses are blockchain-layer** --- Detection requires on-chain monitoring tools (e.g., Forta, Chainalysis, Elliptic), not network IDS/IPS

### Behavioral Detection Guidance (Non-Rule)

Organizations operating Web3 frontends or DeFi platforms should monitor for:

1. **Subresource Integrity (SRI) violations** --- Any third-party script loaded without matching SRI hash
2. **Content Security Policy (CSP) violations** --- Report-URI/report-to endpoints should be monitored for unexpected script sources
3. **Unexpected `eth_sendTransaction` or `eth_signTypedData` RPC calls** --- Monitor browser-level Web3 provider interactions for approval transactions not initiated by application code
4. **Frontend dependency changes** --- CI/CD pipeline monitoring for unexpected changes to `package-lock.json`, `yarn.lock`, or vendored JavaScript bundles
5. **Token approval anomalies** --- On-chain monitoring for `Approval` events with `type(uint256).max` value on stablecoin contracts

### For Blockchain/DeFi Security Teams

The primary consolidation wallet `0xe65b1C586757c5510B60F998Eebb14C1eF71E1eD` and associated staging wallets should be added to on-chain monitoring and alerting systems (Forta agents, Chainalysis KYT, Elliptic Lens) to detect any further fund movement or reuse of attacker infrastructure.

## Remediation

### For Polymarket Users

1. **Revoke token approvals** --- Use tools like [Revoke.cash](https://revoke.cash) to check and revoke any outstanding PUSD or ERC-20 token approvals on Polygon, particularly any approvals granted on or around June 25, 2026
2. **Monitor wallet activity** --- Watch for unauthorized transactions on connected wallets
3. **Contact Polymarket** --- Affected users should contact Polymarket support for reimbursement

### For Web3 Platform Operators

1. **Implement Subresource Integrity (SRI)** --- Pin all third-party scripts with cryptographic hashes
2. **Deploy strict Content Security Policy (CSP)** --- Restrict script-src to known origins; block inline scripts
3. **Vendor security assessment** --- Audit all third-party frontend dependencies and their supply chain security posture
4. **CI/CD integrity monitoring** --- Implement lockfile verification, dependency pinning, and build reproducibility checks
5. **Frontend anomaly detection** --- Deploy browser-level monitoring (e.g., Feroot, Jscrambler, PerimeterX Code Defender) to detect injected or modified scripts in production
6. **Transaction simulation** --- Implement transaction preview/simulation for users before wallet signing to expose fraudulent approvals
7. **Rate limiting and anomaly detection** --- Monitor for unusual patterns of token approval transactions

### For End Users (General)

1. **Review transaction details** --- Always carefully review wallet transaction prompts before signing; be suspicious of unexpected approval requests
2. **Use hardware wallets** --- Hardware wallets require physical confirmation, providing an additional verification step
3. **Limit token approvals** --- Approve only the specific amount needed rather than unlimited allowances

## Sources

- [BleepingComputer: Polymarket customers lose $3 million in supply-chain attack](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)
- [Security Affairs: Third-party breach at Polymarket leads to $2.94M crypto theft](https://securityaffairs.com/194266/security/third-party-breach-at-polymarket-leads-to-2-94m-crypto-theft.html)
- [SecurityWeek: $3 Million Reportedly Stolen in Polymarket Hack](https://www.securityweek.com/3-million-reportedly-stolen-in-polymarket-hack/)
- [Blockonomi: Polymarket Hack: $3M Drained in Supply-Chain Frontend Attack](https://blockonomi.com/polymarket-hack-3m-drained-in-supply-chain-frontend-attack)
- [Cryip: Polymarket Loses $3 Million in Frontend Exploit After Third-Party Vendor Compromise](https://cryip.co/polymarket-frontend-hack-third-party-vendor-3-million-june-2026/)
- [The Next Web: Polymarket confirms hackers stole $3M from users after third-party vendor was compromised](https://thenextweb.com/news/polymarket-hack-3-million-stolen-third-party-breach)
- [Crypto Economy: Polymarket Suffers $2.9M Breach After Script Injection](https://crypto-economy.com/polymarket-suffers-2-9m-breach-after-script-injection-users-set-to-receive-full-refunds/)
- [Our Crypto Talk: Polymarket Hack Drains $3M in PUSD via Frontend Exploit](https://ourcryptotalk.com/news/polymarket-hack-pusd-frontend-exploit)
- [Polymarket Official Statement (X/Twitter)](https://x.com/PolymarketTrade/status/2070155882906730671)

---
*Generated by Actioner --- 2026-06-27*
