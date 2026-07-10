# QuorumVault v2 — signing abstraction & tiered architecture

This package turns the proven v1 Testnet 2-of-2 quorum into production-shaped
code: a swappable signing abstraction where **no plaintext key material ever
touches disk or logs**, and a tiered assurance model that routes each payment to
the right lane by its stakes, with the 2-of-2 quorum kept underneath as the
high-value backstop.

Everything here targets **XRPL Testnet only**. The package itself makes no
network calls; the only place that can broadcast is the demo's opt-in `--submit`
path, and it is hard-wired to the Testnet endpoint.

## Layout

```
quorumvault/
  signing/     the signing seam and its backends
    backend.py         SignerBackend (the interface everything depends on)
    keystore.py        AES-256-GCM + scrypt encrypted keystore (no plaintext at rest)
    local_keystore.py  LocalEncryptedKeystoreBackend (ed25519 or secp256k1)
    kms_backend.py     AwsKmsSignerBackend (non-exportable secp256k1)
    quorum_signer.py   QuorumSigner — combines backends into a multisigned tx
  policy/      the risk rules
    risk_engine.py     v1's three rules (value/whitelist/velocity) + circuit breaker
    rwa_rule.py        the 4th rule: RWA compliance (MPT/Credentials/Domains/Clawback)
    ledger_reader.py   LedgerComplianceReader — resolves that rule's input from live XRPL state
  tiers/       the v2 assurance lanes
    channel_custody.py Payment-Channel lane (audited at open/close only)
    fast_path.py       Velocity-Bounded Fast Path (LastLedgerSequence expiry)
    router.py          TierRouter (picks the lane by value; RWA always -> quorum)
  integrations/
    external_signer.py    QuorumVaultExternalSigner — the XRPL Agent Wallet Skill's ExternalSigner contract
    agent_wallet_ceremony.py  faithful simulation of the skill's six-step signing ceremony
  tools/
    migrate_keystore.py  import plaintext checkpoint -> encrypted keystore, then shred
```

## The one seam that matters

Everything above signing depends only on `SignerBackend`:

```python
class SignerBackend(ABC):
    public_key: str          # XRPL hex pubkey (ED… or 02/03…)
    classic_address: str     # r…
    algorithm: str           # "ed25519" | "secp256k1"
    def sign(self, signing_blob: bytes) -> str: ...   # -> TxnSignature hex
```

`QuorumSigner([backend_a, backend_b]).multisign(tx)` produces a transaction that
is **byte-for-byte identical** to xrpl-py's own `sign(multisign=True)` +
`multisign()` — see `tests/test_quorum_signer.py`. The only thing a backend
changes is *where the signature comes from*. `tests/test_mixed_backend_quorum.py`
proves a single quorum can mix an ed25519 local-keystore signer with a
secp256k1 KMS signer, with the quorum logic above unchanged.

## RWA compliance: live ledger reads

`rwa_rule.py`'s `RwaComplianceRule.evaluate()` stays a pure function over an
already-resolved `RwaTransfer` — no network calls, so it stays fast and fully
testable offline. `ledger_reader.py` is what actually produces that
`RwaTransfer` from real chain state, as the same kind of injectable seam as
`SignerBackend` and `RateProvider`:

```python
class LedgerComplianceReader(ABC):
    def resolve(self, *, mpt_issuance_id, destination,
                required_credentials=None, domain_id=None) -> RwaTransfer: ...
```

`XrplLedgerComplianceReader` implements it against any xrpl-py sync `Client`
(so Testnet vs. Mainnet is the caller's choice, never hardcoded): it reads the
`MPTokenIssuance`'s flags (`lsfMPTRequireAuth`, `lsfMPTCanTransfer`,
`lsfMPTCanClawback`), the destination's `MPToken` (`lsfMPTAuthorized`), and —
if a Permissioned Domain applies — its `AcceptedCredentials`, checking the
destination's actual `Credential` objects (accepted + unexpired). Domain
membership is OR semantics (holding *any one* accepted credential is
sufficient), matching XRPL's own rule; explicit policy-required credentials
are AND semantics (every one must be held), matching `rwa_rule.py`'s existing
check. `StaticComplianceReader` is a labelled placeholder for dry runs,
mirroring `StaticRateProvider`.

**Fails closed.** A network/transport error, or any server response that
isn't a clean success or a well-formed "object not found," raises
`ComplianceReadError` rather than defaulting to "compliant." A confirmed
"doesn't exist" (no `MPToken` for this holder, no matching `Credential`) is a
real negative answer, not a read failure. Field/flag names were verified
against xrpl.org's current ledger-format reference and the `xrpl-py` 5.0.0
request models, not reconstructed from memory — see `tests/test_ledger_reader.py`
(20 tests against a fake client) for the exact ledger JSON shapes exercised.
Scope: MPT-based RWAs only; IOU clawback exposure is the other half of
`RwaTransfer.token_kind` and remains unimplemented until something in
QuorumVault actually moves IOUs.

Two defense-in-depth notes from an adversarial review (flagged, not fail-open):
a malformed-but-"successful" server response blocks via safe defaults
(`Flags` missing → `transfer_disabled=True`) rather than an explicit raise; and
a malformed on-ledger integer/field value raises `ValueError`/`KeyError`
rather than the typed `ComplianceReadError` — it still blocks and never
resolves to "compliant," but a caller catching only `ComplianceReadError`
would see an uncaught exception instead. Wrapping that parse step in
`ComplianceReadError` would make the typed guarantee airtight; not yet done.

**Proven live on Testnet (2026-07-10).** Beyond the fake-client tests,
`XrplLedgerComplianceReader` was wired into `QuorumVaultExternalSigner` and run
against a real MPT issuance (RequireAuth + CanTransfer) through the full Agent
Wallet Skill ceremony: a compliant transfer to an issuer-authorized holder was
delivered on-ledger (tx `6AC230DCEC1B140F7B6CAEC9311FD6E1C1F7DCFDC9F30055615019762A9DC0DB`,
a validated 2-of-2 multisig), and a transfer to an opted-in-but-never-authorized
holder was refused by the signer — driven by the live `destination_authorized=
False` read, the fail-closed guarantee holding against a real server, not a mock.
See `mpt_rwa_demo.py`.

## Security tradeoffs (flagged, not hidden)

1. **ed25519 keys vs. cloud HSM/KMS.** The current Testnet signers are ed25519.
   AWS/GCP KMS can only sign **secp256k1**, not ed25519. So:
   - The **local encrypted keystore** works with the existing ed25519 signers
     today, no migration.
   - Adopting `AwsKmsSignerBackend` (non-exportable key, strongest posture)
     means putting a **secp256k1** key in KMS and adding it to the treasury's
     `SignerListSet`. Because signer entries are per-account, you can migrate
     **one signer at a time**. Alternatively use an ed25519-capable backend
     (HashiCorp Vault transit) — the interface is identical.

2. **Encrypted keystore is weaker than an HSM.** The keystore never writes
   plaintext to disk, but it must decrypt the seed into process memory to sign,
   and Python cannot guarantee that memory is wiped (immutable `str`
   intermediates, allocator reuse, core dumps). This is the *minimum* acceptable
   posture near funds — "secrets-manager-backed keystore" — not the strongest.
   Only KMS/HSM (key never leaves the boundary) closes this gap.

3. **Channel capacity is un-audited exposure.** The Channel-Custody lane audits
   only at open and close. Between them, the Execution Agent's channel key
   single-signs claims up to capacity with no per-payment audit. Therefore the
   **channel capacity is the risk budget** and is bounded by the auditor at open
   (`capacity_cap_drops`); anything larger routes to the 2-of-2 quorum.

A fourth, smaller one worth knowing: `AwsKmsSignerBackend` normalizes KMS's
ECDSA signatures to **low-S** because KMS does not guarantee canonical
signatures and the XRPL rejects high-S. Covered by `tests/test_kms_backend.py`.

## Migrate off plaintext seeds

```bash
export QUORUMVAULT_KEYSTORE_PASSPHRASE='…'          # never stored or echoed
python -m quorumvault.tools.migrate_keystore \
    --checkpoint wallets_checkpoint.json \
    --keystore keystore.json \
    --shred                                          # secure-delete the plaintext after verify
```

The treasury seed is skipped by default (its master key is disabled on-ledger,
so it can no longer sign anything). Note the shred caveat: on SSD/CoW/journaled
filesystems the original bytes may still be recoverable, so for real funds treat
any machine that held the plaintext as needing key rotation.

## Run it

```bash
pip install "xrpl-py>=5" cryptography           # boto3 only if you use the KMS backend
export QUORUMVAULT_KEYSTORE_PASSPHRASE='…'

python testnet_multisig_demo_v2.py              # offline dry run: routing + 2-of-2 multisign
python -m pytest tests/ -q                      # 101 tests, all offline

# Opt-in live Testnet broadcast (Testnet only, double-gated):
export QUORUMVAULT_CONFIRM_TESTNET=yes
export QUORUMVAULT_TREASURY_ADDRESS=r…
python testnet_multisig_demo_v2.py --submit
```

## Not done yet / next

- HSM/KMS is a *reference* adapter tested against a mock; a live KMS run needs a
  secp256k1 key and a `SignerListSet` update on the treasury.
- Human-override path is still the v1 model; production wants SSO + hardware MFA
  (FIDO2/WebAuthn) bound to the tx hash.
- `XrplLedgerComplianceReader` (live RWA reads) — **done**: run against a real
  Testnet MPT issuance through the full ceremony, both the compliant path
  (delivered on-ledger) and the fail-closed refusal of an unauthorized holder
  (see the RWA section above and `mpt_rwa_demo.py`).
- No independent security audit. Required before any of this touches real funds.

## Post-review refinements (2026-07-10)

**Value conversion is injectable, not a constant.** The XRP->RLUSD rate that
every value-based decision depends on (tier routing, fast-path ceiling, the risk
engine's value threshold) is a `RateProvider` — `StaticRateProvider` for Testnet
(explicitly labelled `is_live=False`) or `CallableRateProvider` for a live feed,
which raises `StaleRateError` rather than routing on a price older than
`max_age_s`. No more `XRP_TO_RLUSD_RATE = 0.55` duplicated across the router,
fast path, and risk engine.

**The local keystore no longer retains the passphrase.**
`LocalEncryptedKeystoreBackend` resolves it on demand instead of holding it for
the life of the object — the env-var path holds nothing at rest, and a
provider callable can pull from a keyring or secrets manager instead.

**Backend decision: local encrypted keystore only, for now.** No AWS KMS
migration before the security audit; that choice gets revisited at the audit
(leaning toward HashiCorp Vault over KMS, since Vault supports ed25519
natively and the treasury's signers already do too). Plaintext migration
(`migrate_keystore --shred`) is safe to run whenever you're ready to move off
the checkpoint file.

## Integration: XRPL Agent Wallet Skill (ExternalSigner) — proven on Testnet

Ripple's XRPL Agent Wallet Skill (xrpl.org/docs/agents/xrpl-agent-wallet-skill)
is explicit that multisig is out of scope: "Multisig. Not in scope ... the
developer needs a dedicated multisig flow." QuorumVault is that flow.

`quorumvault/integrations/external_signer.py` implements the skill's own
`ExternalSigner` contract — `{ address: string; sign(tx) ->
Promise<{tx_blob, hash}> }` — backed by the full stack above: `TierRouter`
picks the lane, `RiskEngine` (now RWA-aware) evaluates it, and only a GREEN
verdict produces `QuorumSigner.multisign()`'s output; anything else raises
`ExternalSignerRefused` rather than returning a signature, i.e. Signature_2 is
withheld, not just discouraged. `quorumvault/integrations/agent_wallet_ceremony.py`
is a faithful Python simulation of the skill's documented six-step ceremony:
receive tx + apply the default SourceTag (20260530) unless one is already set,
match the signer to the tx's Account, autofill, render the skill's exact
preview block, get human confirmation, sign and persist the hash *before*
submitting, then `submitAndWait`.

**Decision (a vs b).** The skill is a Claude-agent skill — prose plus xrpl.js
snippets — and its `ExternalSigner` is a contract the *host* provides. Two
ways to prove QuorumVault satisfies it: (a) a thin xrpl.js/TypeScript shim
that RPCs into QuorumVault so it sits behind a real Claude agent running the
actual skill, or (b) a faithful Python-side simulation of the ceremony,
driving the same `ExternalSigner` object directly. We built (b): it proves
the contract end-to-end to a real on-ledger hash with no TS<->Python bridge to
stand up and nothing to fork in the skill itself. Because
`QuorumVaultExternalSigner` already has the exact `ExternalSigner` shape, (a)
is a transport wrapper away, not a proof gap — documented here as the
production path rather than built for this round.

**Proven on Testnet.** A fresh 2-of-2 treasury (`SignerListSet`, master key
disabled), signer seeds in an encrypted keystore, run through the ceremony end
to end: a validated 2-of-2 multisig Payment via the skill's own flow — tx
`B52360E50C4C1B2F0A7AEBD4168C71574B163089C6E151EA6263DD7EFE49582B`.
Independently re-queried on-ledger: validated, `tesSUCCESS`, empty
`SigningPubKey`, 2 `Signers` (ed25519), `SourceTag` 20260530.

**Hardened after an adversarial review.** Two real bugs were found and fixed
in `external_signer.py` (nothing else touched): the transaction-intent parser
could default an unparsed amount to `0.0` instead of refusing, making the
value check vacuous for any non-Payment or IOU/MPT-typed-object transaction —
closed by refusing outright (`ExternalSignerRefused`) on any unparseable
amount or missing destination, never defaulting to zero. And the RWA rule
could be silently bypassed because nothing wired a real `RwaTransfer` into
non-Payment-shaped or MPT transactions — closed by adding a
`compliance_reader` parameter the signer now requires (fail-closed) before it
will sign any MPT transfer at all. `signable_transaction_types` now also
defaults to `{"Payment"}` and is checked *before* risk scoring, so an
unsupported transaction type (e.g. `SignerListSet`) is refused outright rather
than ever reaching the risk engine — covered by a regression test that
deliberately whitelists the treasury address to prove it's the type gate, not
the value/whitelist checks, doing the refusing. +17 adversarial tests, 101
total, all passing.