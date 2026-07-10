# XRPL Discord Outreach Post — QuorumVault
Post to: discord.gg/xrpl (dev-showcase / relevant channel)

---

## Short version

**QuorumVault — safe at any speed, honest at any scale: tiered custody control for AI treasury agents on XRPL**

Built a self-custody control layer so an AI treasury agent can never move funds unilaterally — an independent Auditor Agent has to agree via a real on-ledger 2-of-2 quorum before anything broadcasts. Proved the multisig mechanics for real on Testnet (not simulated): SignerListSet quorum, master key disabled, and a multisigned Payment signed by two independent keys. Since then, v2 is built and tested, not just planned: a signing abstraction (encrypted local keystore + AWS KMS, interchangeable, byte-identical multisign output) plus three tiers — Payment-Channel micropayments, a velocity-bounded fast path, and an MPT/Credentials-aware RWA rule — all backstopped by the same 2-of-2 quorum, covered by 101 offline tests.

Tx: https://testnet.xrpl.org/transactions/A71FEBAC99F8C8A04920731B844678207E94036A8A037A6F531405DBC55FC198

Repo (signing abstraction, tiers, 101 tests, plus the original 7-scenario risk-policy simulation): https://github.com/QuorumVaultXRPL/quorumvault

Would love feedback from anyone else building agentic payment/custody infra on XRPL.

---

## Long version

**QuorumVault: cryptographic guarantees instead of risk scores for AI treasury agents**

Most AI agent payment safety tools today work by scoring a transaction's risk and forwarding it through a single point of custody if the score is low enough — a solid pattern for high-frequency, low-value machine payments. QuorumVault started from a different case: infrequent, high-value corporate treasury transfers, where the cost of one bad outcome justifies requiring two cryptographically independent parties to agree, not one model's confidence score.

The design principle: the entity that decides a transaction is safe (the Auditor Agent) must never be the entity that can sign it alone. An Execution Agent proposes transactions and holds Signature_1; an independent Auditor Agent evaluates every proposal against risk policy and decides whether Signature_2 gets produced; the treasury account requires both. A flagged transaction can be released only by a Compliance Officer whose override is cryptographically bound to that exact tx hash — it can't be replayed against a different transaction.

We just took this off paper and onto XRPL Testnet for real:

- Real `SignerListSet` establishing a 2-of-2 quorum on a treasury account (`E22459B72B3F8E5D66BAAC47C00174703F6D15E4167F8AEACBE6B0E80CB4A88B`)
- Treasury's master key disabled so multisig is mandatory, not optional (`2111BBA70A88950E0CE41DFF5D1681C9219BEA55288C90966BC0223DD7C1CC73`)
- A Payment independently signed by both signer accounts, combined, and submitted — neither key alone could have moved the funds (`A71FEBAC99F8C8A04920731B844678207E94036A8A037A6F531405DBC55FC198`)

Explorer: https://testnet.xrpl.org/transactions/A71FEBAC99F8C8A04920731B844678207E94036A8A037A6F531405DBC55FC198

**Where it's gone since — v2, built and tested:** a single risk model doesn't fit every transaction — a machine paying a cent for an API call and a treasury moving six figures aren't the same problem. v2 splits QuorumVault into tiers that match XRPL's own primitives to the stakes: a Channel-Custody Lane over Payment Channels for high-frequency low-value agent traffic (audited at channel open/close, not per-payment), a Velocity-Bounded fast path tied to `LastLedgerSequence` for mid-value transfers, and a compliance-aware rule for Real World Assets built on MPTs, Credentials, and Permissioned Domains. All of it sits on the same 2-of-2 quorum as the backstop — and none of it is a design doc anymore. A `SignerBackend` abstraction makes an encrypted local keystore and AWS KMS interchangeable, producing multisigned transactions byte-for-byte identical to XRPL's own native output, and 101 automated, fully offline tests back every claim above.

**Update — QuorumVault now plugs into Ripple's XRPL Agent Wallet Skill.** The official Agent Wallet Skill is explicit that multisig isn't in scope — "the developer needs a dedicated multisig flow." QuorumVault now implements that flow directly: `QuorumVaultExternalSigner` satisfies the skill's own `ExternalSigner` contract (`address`, `sign(tx) -> {tx_blob, hash}`), and a full run through the skill's documented six-step ceremony (autofill, exact preview format, human confirm, sign, persist-hash-before-submit, `submitAndWait`) produced a validated 2-of-2 multisig Payment on Testnet — tx `B52360E50C4C1B2F0A7AEBD4168C71574B163089C6E151EA6263DD7EFE49582B`.

---

**RWA rule now proven live, not just against a fake client.** Created a real MPT issuance (RequireAuth + CanTransfer) on Testnet and ran it through the full Agent Wallet Skill ceremony with a live `XrplLedgerComplianceReader`: a compliant transfer to an authorized holder delivered on-ledger (2-of-2 multisig, tx `6AC230DCEC1B140F7B6CAEC9311FD6E1C1F7DCFDC9F30055615019762A9DC0DB`), and a transfer to an opted-in-but-never-authorized holder was refused by the signer — the refusal driven by the live `destination_authorized=False` read. That's the fail-closed guarantee holding against a real server.
