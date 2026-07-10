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

Core logic (risk policy, circuit breaker, compound risk accumulation, human override bound to a specific tx hash) is implemented and demonstrated in a 7-scenario simulation: `xrpl_auditor_production_blueprint.py` in the repo above.

**Real on-ledger proof (XRPL Testnet):**
We've moved beyond simulation and executed the actual multisig mechanics on XRPL Testnet — not a mock:

1. Three funded Testnet accounts: a treasury account plus two independent signer accounts (standing in for the Execution Agent and Auditor Agent).
2. A real `SignerListSet` transaction establishing a 2-of-2 quorum on the treasury account — tx hash `E22459B72B3F8E5D66BAAC47C00174703F6D15E4167F8AEACBE6B0E80CB4A88B`.
3. The treasury's master key disabled (`AccountSet`, `asfDisableMasterKey`), so multisig is the *only* way to move funds from that point forward — tx hash `2111BBA70A88950E0CE41DFF5D1681C9219BEA55288C90966BC0223DD7C1CC73`.
4. A real `Payment` transaction signed independently by both signers, combined, and submitted — neither signer could have moved funds alone — tx hash `A71FEBAC99F8C8A04920731B844678207E94036A8A037A6F531405DBC55FC198`.

Explorer link: https://testnet.xrpl.org/transactions/A71FEBAC99F8C8A04920731B844678207E94036A8A037A6F531405DBC55FC198

**Where it's gone since — v2, built and tested (not a roadmap slide):**
The architecture above has moved from a validated design into production-shaped code. A `SignerBackend` abstraction treats an encrypted local keystore and AWS KMS as interchangeable signing backends, producing multisigned transactions byte-for-byte identical to XRPL's own native output — verified directly against xrpl-py's own signing path in the test suite. On top of that foundation sit three further assurance tiers: a Channel-Custody lane for high-frequency, low-value payments via Payment Channels (audited at open/close only); a Velocity-Bounded Fast Path for mid-value transactions with on-ledger `LastLedgerSequence` expiry; and an RWA compliance rule aware of MPTs, Credentials, Permissioned Domains, and Clawback — now wired to real ledger reads (`XrplLedgerComplianceReader`) rather than just a supplied compliance context. All of it routes back through the same 2-of-2 quorum backstop, and all of it is covered by 84 automated, fully offline tests — public in the repo above, no code access request required.

**Ecosystem integration — Ripple's XRPL Agent Wallet Skill:**
Ripple's official XRPL Agent Wallet Skill is the signing layer for Claude agents on XRPL, and it draws one explicit boundary: *"Multisig. Not in scope. If you're handed a multisig transaction (one expecting a Signers array), refuse and tell the human that multisig signing is not handled by this skill — the developer needs a dedicated multisig flow."* QuorumVault is precisely that dedicated multisig flow. Rather than fork the skill, we implement its own production signing contract — the `ExternalSigner` interface it defines for HSM/KMS signers — and run its documented signing ceremony end to end, with the single "sign" step becoming QuorumVault's full risk-gated 2-of-2 multisig, invisible to the agent. Proven on XRPL Testnet: a validated 2-of-2 multisig Payment produced through the skill's own ceremony — tx hash `B52360E50C4C1B2F0A7AEBD4168C71574B163089C6E151EA6263DD7EFE49582B` (https://testnet.xrpl.org/transactions/B52360E50C4C1B2F0A7AEBD4168C71574B163089C6E151EA6263DD7EFE49582B).

**Why now:**
Ripple's own XRPL AI Starter Kit (June 2026) names multisig, deposit authorization, and escrow-grade controls as exactly what institutions need before letting agents transact autonomously. QuorumVault is a working, tested implementation of that control layer, not a proposal for one — built on the same primitives XRPL is pointing developers toward.

**Not yet done, in the open:**
A live AWS KMS run against a real secp256k1 signer (the current backend is tested against a mock); the RWA ledger reader run against a real server (it's tested against a fake XRPL client today, not yet a live one — there's no MPT issuance on Testnet to point it at yet); SSO and hardware MFA (FIDO2/WebAuthn) for human overrides; and, the hard prerequisite before any of this touches real funds, an independent security audit.

**What we're looking for:**
A technical design review and honest feedback on the architecture — the signing abstraction, the tiered model, where it holds up and where it doesn't — from people who work with these primitives daily. If that review finds real merit, we're open to a conversation about how to proceed from there, whether that's grant support, accelerator mentorship, or something else. No specific ask beyond that starting point.

**Contact:** Jason Michael Jung — jasonjung0019@gmail.com — https://github.com/QuorumVaultXRPL/quorumvault
