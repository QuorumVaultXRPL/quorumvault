"""Live Testnet proof: the Credential + Permissioned Domain paths of
XrplLedgerComplianceReader, against a real server (not the fake client tests use).

mpt_rwa_demo.py (2026-07-10) already proved the MPT-issuance/authorization path live
(real tx hashes on file). This script proves the two paths that were NOT covered by
that run: _holds_credential (required_credentials) and _get_domain_accepted_credentials
(domain_id), which resolve() only exercises when the caller actually supplies them.

Creates one real XLS-70 Credential (issued + accepted) and one real Permissioned
Domain that accepts it, plus a second subject who never gets the credential, then
calls XrplLedgerComplianceReader.resolve() directly against both and confirms the
result matches real on-ledger truth. Testnet only. Resumable via a state file.
"""

from __future__ import annotations

import json
import os
import sys

from xrpl.clients import JsonRpcClient
from xrpl.core.addresscodec import decode_classic_address
from xrpl.models.transactions import (
    CredentialAccept,
    CredentialCreate,
    MPTokenIssuanceCreate,
    PermissionedDomainSet,
)
from xrpl.models.transactions.mptoken_issuance_create import MPTokenIssuanceCreateFlag
from xrpl.models.transactions.permissioned_domain_set import (
    Credential as PDCredential,
)
from xrpl.transaction import autofill, sign, submit_and_wait
from xrpl.wallet import Wallet, generate_faucet_wallet

from quorumvault.policy.intent import Credential
from quorumvault.policy.ledger_reader import XrplLedgerComplianceReader

TESTNET = "https://s.altnet.rippletest.net:51234"
EXPLORER = "https://testnet.xrpl.org/transactions"
STATE = os.environ.get("CRED_DEMO_STATE", "/tmp/cred_domain_state.json")
CRED_TYPE = "RWA_ACCREDITED"

client = JsonRpcClient(TESTNET)


def log(m):
    print(m, flush=True)


def load_state():
    return json.load(open(STATE)) if os.path.exists(STATE) else {}


def save(state):
    json.dump(state, open(STATE, "w"), indent=2)


def compute_mpt_issuance_id(issuer: str, sequence: int) -> str:
    return (sequence.to_bytes(4, "big") + decode_classic_address(issuer)).hex().upper()


def submit_single(tx, wallet, label):
    r = submit_and_wait(sign(autofill(tx, client), wallet), client)
    code = r.result["meta"]["TransactionResult"]
    log(f"  {label}: {code} ({r.result['hash']})")
    if code != "tesSUCCESS":
        sys.exit(f"{label} failed: {code}")
    return r


def domain_id_from_meta(meta) -> str:
    for node in meta.get("AffectedNodes", []):
        created = node.get("CreatedNode")
        if created and created.get("LedgerEntryType") == "PermissionedDomain":
            return created["LedgerIndex"]
    raise RuntimeError("No PermissionedDomain CreatedNode in tx metadata")


def main():
    state = load_state()

    # P1 - fund 3 accounts (resumable).
    accounts = ["issuer", "subject_ok", "subject_bad"]
    state.setdefault("seeds", {})
    for n in accounts:
        if n not in state["seeds"]:
            log(f"P1: funding {n} via Testnet faucet...")
            w = generate_faucet_wallet(client, debug=False)
            state["seeds"][n] = w.seed
            state[n] = w.address
            save(state)
            log(f"  {n}={w.address}")
    if len(state["seeds"]) < len(accounts):
        log("P1 incomplete; re-run to fund the rest.")
        return

    issuer = Wallet.from_seed(state["seeds"]["issuer"])
    subject_ok = Wallet.from_seed(state["seeds"]["subject_ok"])
    subject_bad = Wallet.from_seed(state["seeds"]["subject_bad"])

    # P2 - issuer creates a minimal MPT issuance (resolve() requires one to exist;
    # this test isn't about the MPT path, already proven live in mpt_rwa_demo.py).
    if not state.get("issuance_id"):
        log("P2: issuer creates a minimal MPTokenIssuance...")
        create = MPTokenIssuanceCreate(
            account=issuer.address,
            flags=MPTokenIssuanceCreateFlag.TF_MPT_CAN_TRANSFER,
            asset_scale=2, maximum_amount="1000000000", transfer_fee=0,
        )
        filled = autofill(create, client)
        seq = filled.sequence
        r = submit_and_wait(sign(filled, issuer), client)
        code = r.result["meta"]["TransactionResult"]
        if code != "tesSUCCESS":
            sys.exit(f"MPTokenIssuanceCreate failed: {code}")
        computed = compute_mpt_issuance_id(issuer.address, seq)
        meta_id = r.result["meta"].get("mpt_issuance_id")
        log(f"  create: {code} ({r.result['hash']})")
        state["issuance_id"] = meta_id or computed
        state["issuance_hash"] = r.result["hash"]
        save(state)

    # P3 - issuer issues the Credential to subject_ok.
    if not state.get("credential_created"):
        log(f"P3: issuer issues Credential ({CRED_TYPE}) to subject_ok...")
        r = submit_single(
            CredentialCreate(
                account=issuer.address, subject=subject_ok.address,
                credential_type=CRED_TYPE.encode("utf-8").hex().upper(),
            ),
            issuer, "CredentialCreate",
        )
        state["credential_created"] = True
        state["credential_create_hash"] = r.result["hash"]
        save(state)

    # P4 - subject_ok accepts it (XLS-70: not valid until accepted).
    if not state.get("credential_accepted"):
        log("P4: subject_ok accepts the Credential...")
        r = submit_single(
            CredentialAccept(
                account=subject_ok.address, issuer=issuer.address,
                credential_type=CRED_TYPE.encode("utf-8").hex().upper(),
            ),
            subject_ok, "CredentialAccept",
        )
        state["credential_accepted"] = True
        state["credential_accept_hash"] = r.result["hash"]
        save(state)

    # P5 - issuer creates a Permissioned Domain that accepts this credential type.
    if not state.get("domain_id"):
        log("P5: issuer creates a PermissionedDomain accepting this credential...")
        r = submit_single(
            PermissionedDomainSet(
                account=issuer.address,
                accepted_credentials=[
                    PDCredential(
                        issuer=issuer.address,
                        credential_type=CRED_TYPE.encode("utf-8").hex().upper(),
                    )
                ],
            ),
            issuer, "PermissionedDomainSet",
        )
        domain_id = domain_id_from_meta(r.result["meta"])
        log(f"  domain_id={domain_id}")
        state["domain_id"] = domain_id
        state["domain_set_hash"] = r.result["hash"]
        save(state)

    # subject_bad: deliberately never receives or accepts any credential.

    log("\n==== LIVE READ: XrplLedgerComplianceReader.resolve() against real Testnet ====")
    reader = XrplLedgerComplianceReader(client)
    required = [Credential(issuer=issuer.address, credential_type=CRED_TYPE)]

    log("\n-- subject_ok (holds accepted credential, is in the domain) --")
    ok = reader.resolve(
        mpt_issuance_id=state["issuance_id"], destination=subject_ok.address,
        required_credentials=required, domain_id=state["domain_id"],
    )
    log(f"  destination_credentials : {ok.destination_credentials}")
    log(f"  destination_in_domain   : {ok.destination_in_domain}")
    assert len(ok.destination_credentials) == 1, "expected subject_ok's credential to be found"
    assert ok.destination_in_domain is True, "expected subject_ok to be recognized as in-domain"

    log("\n-- subject_bad (no credential at all) --")
    bad = reader.resolve(
        mpt_issuance_id=state["issuance_id"], destination=subject_bad.address,
        required_credentials=required, domain_id=state["domain_id"],
    )
    log(f"  destination_credentials : {bad.destination_credentials}")
    log(f"  destination_in_domain   : {bad.destination_in_domain}")
    assert bad.destination_credentials == [], "expected subject_bad to hold no credentials"
    assert bad.destination_in_domain is False, "expected subject_bad to NOT be in-domain"

    state["verified_ok"] = True
    save(state)

    log("\n==== SUMMARY (all real Testnet tx, independently re-queryable) ====")
    log(f"issuance_id          : {state['issuance_id']}  ({EXPLORER}/{state['issuance_hash']})")
    log(f"CredentialCreate     : {EXPLORER}/{state['credential_create_hash']}")
    log(f"CredentialAccept     : {EXPLORER}/{state['credential_accept_hash']}")
    log(f"PermissionedDomainSet: {EXPLORER}/{state['domain_set_hash']}  domain_id={state['domain_id']}")
    log(f"issuer               : {issuer.address}")
    log(f"subject_ok           : {subject_ok.address}")
    log(f"subject_bad          : {subject_bad.address}")
    log("Both live reads matched real on-ledger truth. PASS.")


if __name__ == "__main__":
    main()
