# RippleX Ecosystem Programs Submission — QuorumVault

Submit at: https://submit.xrplgrants.org/submit ("Tell Us About Your Company")
Priority areas: AI & Agentic Commerce; Real World Assets

---

**Company / Project name:** QuorumVault

**One-line description:**
Safe at any speed, honest at any scale — a self-custody risk auditor and circuit breaker for AI treasury agents on the XRP Ledger, giving every transaction a cryptographic guarantee instead of a probabilistic risk score.

**Website / Repo:**
https://github.com/QuorumVaultXRPL/quorumvault

**Contact:** Jason Michael Jung — jasonjung0019@gmail.com

**The problem:**
Autonomous trading and treasury agents are increasingly authorized to move real capital — XRP, RLUSD, and other assets — without a human in the loop on every transaction. Today's dominant safety pattern for this is probabilistic: score a transaction's risk, then forward it through a single point of custody if the score is low enough. That's useful for high-frequency, low-value machine payments, but it has a ceiling — a well-crafted attack or a confident-sounding hallucination can still score as "low risk," and a single point of custody remains a single point of failure.

**The insight:**
XRPL itself was built on a similar premise: give the network genuinely different tools for genuinely different jobs, rather than one mechanism stretched to cover every case — fast consensus for everyday payments, and separate, purpose-built primitives (escrow, payment channels, multisig, and now MPTs, Credentials, and Permissioned Domains) for the situations that need something stronger. QuorumVault applies the same logic to AI treasury control: instead of one risk model trying to be safe at every transaction size and every speed, QuorumVault gives an institution *tiers* of assurance and lets the transaction's own stakes pick the tier. The result is a system that's safe at any speed, and honest at any scale — a micropayment and a treasury transfer aren't policed the same way, because they aren't the same problem.

**The solution — v1, live today:**
QuorumVault's foundation targets infrequent, high-value corporate treasury transactions, where the cost of a single bad outcome justifies requiring two cryptographically independent parties to agree — not one risk model. The architecture separates the entity that decides whether a transaction is safe (the Auditor Agent) from the entity that can sign it (a 2-of-2 multisig quorum), so no single compromised component — including the Auditor Agent itself — can move funds alone. Unlike custody-as-a-service models, the institution never hands wallet control to a third party at all.

Core logic (risk policy, circuit breaker, compound risk accumulation, human override bound to a specific tx hash) is implemented in `quorumvault/policy/` and covered by the automated test suite referenced below. The earliest version of this logic was proven out in a standalone 7-scenario simulation before any ledger integration existed (`legacy/xrpl_auditor_production_blueprint.py` in the repo); that prototype is superseded by the tested, Testnet-proven package described from here on.

**Real on-ledger proof (XRPL Testnet):**
We've moved beyond simulation and executed the actual multisig mechanics on XRPL Testnet — not a mock:

1. Three funded Testnet accounts: a treasury account plus two independent signer accounts (standing in for the Execution Agent and Auditor Agent).
2. A real `SignerListSet` transaction establishing a 2-of-2 quorum on the treasury account — tx hash `E22459B72B3F8E5D66BAAC47C00174703F6D15E4167F8AEACBE6B0E80CB4A88B`.
3. The treasury's master key disabled (`AccountSet`, `asfDisableMasterKey`), so multisig is the *only* way to move funds from that point forward — tx hash `2111BBA70A88950E0CE41DFF5D1681C9219BEA55288C90966BC0223DD7C1CC73`.
4. A real `Payment` transaction signed independently by both signers, combined, and submitted — neither signer could have moved funds alone — tx hash `A71FEBAC99F8C8A04920731B844678207E94036A8A037A6F531405DBC55FC198`.

Explorer link: https://testnet.xrpl.org/transactions/A71FEBAC99F8C8A04920731B844678207E94036A8A037A6F531405DBC55FC198

**Where it's gone since — v2, built and tested (not a roadmap slide):**
The architecture above has moved from a validated design into production-shaped code. A `SignerBackend` abstraction treats an encrypted local keystore and AWS KMS as interchangeable signing backends, producing multisigned transactions byte-for-byte identical to XRPL's own native output — verified directly against xrpl-py's own signing path in the test suite. On top of that foundation sit three further assurance tiers: a Channel-Custody lane for high-frequency, low-value payments via Payment Channels (audited at open/close only); a Velocity-Bounded Fast Path for mid-value transactions with on-ledger `LastLedgerSequence` expiry; and an RWA compliance rule aware of MPTs, Credentials, Permissioned Domains, and Clawback — wired to real ledger reads (`XrplLedgerComplianceReader`) and **proven end-to-end on XRPL Testnet against a real MPT issuance**: a compliant transfer to an issuer-authorized holder delivered on-ledger (tx `6AC230DCEC1B140F7B6CAEC9311FD6E1C1F7DCFDC9F30055615019762A9DC0DB`), and a transfer to an opted-in-but-never-authorized holder refused by the signer, driven by a live authorization read — the fail-closed guarantee holding against a real server, not a mock. All of it routes back through the same 2-of-2 quorum backstop, and all of it is covered by 101 automated, fully offline tests — public in the repo above, no code access request needed.

**Also live: Ripple's own XRPL Agent Wallet Skill.** The skill explicitly excludes multisig ("the developer needs a dedicated multisig flow"); QuorumVault is that flow. `QuorumVaultExternalSigner` satisfies the skill's `ExternalSigner` contract, and a full run through its documented six-step signing ceremony produced a validated 2-of-2 multisig Payment on Testnet — tx `B52360E50C4C1B2F0A7AEBD4168C71574B163089C6E151EA6263DD7EFE49582B`.

We'd welcome the chance to walk through the code and the on-ledger proof directly, and to talk through how QuorumVault fits RippleX's AI & Agentic Commerce and Real World Assets priority areas.
