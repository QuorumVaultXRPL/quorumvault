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
- `XrplLedgerComplianceReader` (live RWA reads) is written and tested against a
  fake client (`tests/test_ledger_reader.py`), but not yet run against a real
  server — no MPT issuance has actually been created on Testnet to point it at.
  That live run, plus wiring it into `testnet_multisig_demo_v2.py`'s dry-run
  path, is the next step.
- No independent security audit. Required before any of this touches real funds.

## Post-review refinements (2026-07-10)

**Value conversion is injectable, not a constant.** The XRP->RLUSD rate that
every value-based decision depends on (tier routing, fast-path ceiling, the risk
engine's value threshold) is a `RateProvider`, not a hardcoded number. A stale
rate would otherwise silently misroute a transaction into a less-audited tier, or
let an over-threshold transfer skip the value gate. `StaticRateProvider` is a
labelled Testnet placeholder (`is_live == False`); for real funds inject a
`CallableRateProvider` wrapping a live feed, with `max_age_s` set so a stale
price raises `StaleRateError` instead of being routed on.

**Keystore nuance (4th tradeoff).** The backend no longer retains the passphrase
for its lifetime. On the production path (no explicit passphrase) it resolves
`QUORUMVAULT_KEYSTORE_PASSPHRASE` fresh on each `sign()` and stores no secret; an
explicit provider callable (e.g. an OS-keyring lookup) is invoked per signature.
The env var itself remains the secret's home, so protect the process environment.

**Backend decision (recorded).** Local encrypted keystore only for now — it's
ed25519-native (zero migration) and already removes the actual problem (the
plaintext seed file). Do **not** migrate to AWS KMS before the security audit
that gates real funds: solving HSM custody early means a real operational step
(new secp256k1 key + `SignerListSet` update) to protect funds that aren't there
yet. Revisit KMS vs. Vault at the audit, leaning Vault if forced to choose today
(native ed25519, no forced key-scheme migration); reach for AWS KMS first only if
standardizing on AWS for other reasons.

## Integration: XRPL Agent Wallet Skill (ExternalSigner) — proven on Testnet

Ripple's [XRPL Agent Wallet Skill](https://xrpl.org/docs/agents/xrpl-agent-wallet-skill)
is the wallet/signing layer for Claude agents on XRPL. It deliberately excludes
multisig:

> "Multisig. Not in scope. If you're handed a multisig transaction (one
> expecting a Signers array), refuse and tell the human that multisig signing is
> not handled by this skill — the developer needs a dedicated multisig flow."

QuorumVault is that dedicated flow. `quorumvault/integrations/external_signer.py`
implements the skill's own production signing contract —
`ExternalSigner { address; sign(tx) -> {tx_blob, hash} }` — with the `sign` step
backed by QuorumVault's risk-gated 2-of-2 multisig (Auditor gate + TierRouter +
QuorumSigner). `agent_wallet_ceremony.py` runs the skill's documented six-step
ceremony (autofill → exact preview block → confirm → sign → persist-hash →
submitAndWait); `agent_wallet_skill_demo.py` runs it end to end on Testnet.

**Proven on Testnet:** the ceremony produced a *validated 2-of-2 multisig Payment*
(empty `SigningPubKey`, two `Signers`), with `SourceTag 20260530` applied per the
skill — tx `B52360E50C4C1B2F0A7AEBD4168C71574B163089C6E151EA6263DD7EFE49582B`
(https://testnet.xrpl.org/transactions/B52360E50C4C1B2F0A7AEBD4168C71574B163089C6E151EA6263DD7EFE49582B).

**Decision (a vs b):** the ceremony is realized in Python (option **b**), because
QuorumVault is Python and this proves the contract end-to-end to a real hash with
no TS↔Python bridge. The signer object is exactly the `ExternalSigner` shape, so a
thin xrpl.js shim RPC-ing into it (option **a** — sitting behind a live Claude
agent running the skill) is transport, not proof, and is the documented
production path.

**Hardened after an adversarial review.** The signer default-denies by
transaction type — it only ever risk-gates `Payment`; everything else
(`SignerListSet`, `AccountSet`, `SetRegularKey`, …) is refused outright, before
the risk score even runs, because those transactions carry no "amount" for a
value check to mean anything. IOU/MPT amounts are parsed from the transaction's
canonical XRPL form so they're valued correctly rather than defaulting to zero.
An MPT (RWA) transfer is refused unless a `LedgerComplianceReader` is explicitly
wired in — the RWA rule runs against a real resolved `RwaTransfer` or the
signer doesn't sign, never the rule silently skipped. See
`tests/test_external_signer_adversarial.py` for the regression tests, including
one that whitelists the treasury address specifically to prove the type refusal
doesn't secretly depend on that *not* being the case.
