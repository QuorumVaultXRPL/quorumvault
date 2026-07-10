"""Live Testnet RWA proof: a real MPT run through the Agent Wallet Skill ceremony.

Closes the "RWA rule tested against a fake client only" gap. Creates a real
MPTokenIssuance (RequireAuth + CanTransfer) on Testnet, wires the *live*
XrplLedgerComplianceReader into QuorumVaultExternalSigner, and runs two payments
through the real agent_wallet_ceremony.run_ceremony:

  1. treasury -> issuer-authorized exec_signer  => compliant => validated tx hash
  2. treasury -> opted-in-but-never-authorized  => ExternalSignerRefused, driven
     by a live ledger read (destination_authorized=False), not a mock. This is
     the one that proves fail-closed holds against a real server.

Testnet only. Resumable via a state file (each on-ledger step is checkpointed),
so it can be run across several invocations under a short shell timeout.
"""

from __future__ import annotations

import json
import os
import sys

from xrpl.clients import JsonRpcClient
from xrpl.core.addresscodec import decode_classic_address
from xrpl.models.amounts import MPTAmount
from xrpl.models.requests import AccountInfo, LedgerEntry
from xrpl.models.requests.ledger_entry import MPToken as MPTokenQuery
from xrpl.models.transactions import (
    AccountSet,
    MPTokenAuthorize,
    MPTokenIssuanceCreate,
    Payment,
    SignerListSet,
)
from xrpl.models.transactions.mptoken_issuance_create import MPTokenIssuanceCreateFlag
from xrpl.models.transactions.signer_list_set import SignerEntry
from xrpl.transaction import autofill, sign, submit_and_wait
from xrpl.wallet import Wallet, generate_faucet_wallet

from quorumvault.integrations.agent_wallet_ceremony import run_ceremony
from quorumvault.integrations.external_signer import (
    ExternalSignerRefused,
    QuorumVaultExternalSigner,
)
from quorumvault.policy.ledger_reader import (
    LSF_MPTOKEN_AUTHORIZED,
    XrplLedgerComplianceReader,
)
from quorumvault.policy.risk_engine import RiskEngine
from quorumvault.signing.keystore import EncryptedKeystore
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.tiers.router import TierRouter

TESTNET = "https://s.altnet.rippletest.net:51234"
EXPLORER = "https://testnet.xrpl.org/transactions"
STATE = os.environ.get("MPT_DEMO_STATE", "/tmp/mpt_rwa_state.json")
KEYSTORE = os.environ.get("MPT_DEMO_KEYSTORE", "/tmp/mpt_rwa_keystore.json")
os.environ.setdefault("QUORUMVAULT_KEYSTORE_PASSPHRASE", "mpt-rwa-demo-passphrase")

client = JsonRpcClient(TESTNET)


def log(m):
    print(m, flush=True)


def load_state():
    return json.load(open(STATE)) if os.path.exists(STATE) else {}


def save(state):
    json.dump(state, open(STATE, "w"), indent=2)


def compute_mpt_issuance_id(issuer: str, sequence: int) -> str:
    # Per xrpl.org: 192-bit = Sequence (4 bytes BE) + issuer AccountID (20 bytes).
    return (sequence.to_bytes(4, "big") + decode_classic_address(issuer)).hex().upper()


def submit_single(tx, wallet, label):
    r = submit_and_wait(sign(autofill(tx, client), wallet), client)
    code = r.result["meta"]["TransactionResult"]
    log(f"  {label}: {code} ({r.result['hash']})")
    if code != "tesSUCCESS":
        sys.exit(f"{label} failed: {code}")
    return r


def mptoken_exists(issuance_id, account):
    r = client.request(LedgerEntry(mptoken=MPTokenQuery(mpt_issuance_id=issuance_id, account=account)))
    return r.is_successful()


def mptoken_authorized(issuance_id, account):
    r = client.request(LedgerEntry(mptoken=MPTokenQuery(mpt_issuance_id=issuance_id, account=account)))
    if not r.is_successful():
        return False
    node = r.result.get("node", r.result)
    return bool(int(node.get("Flags", 0)) & LSF_MPTOKEN_AUTHORIZED)


def build_signer(state):
    keystore = EncryptedKeystore.load(KEYSTORE)
    backends = [
        LocalEncryptedKeystoreBackend(keystore, "exec_signer"),
        LocalEncryptedKeystoreBackend(keystore, "auditor_signer"),
    ]
    return QuorumVaultExternalSigner(
        treasury_address=state["treasury"],
        quorum_signer=QuorumSigner(backends),
        # Whitelist BOTH destinations so the ONLY thing that can refuse the
        # unauthorized one is the live RWA read, not an untrusted-destination flag.
        risk_engine=RiskEngine(
            whitelist=[state["exec_signer"], state["unauth"]],
            amount_threshold_rlusd=5000, frequency_limit=50,
        ),
        router=TierRouter(channel_ceiling_rlusd=100, fast_path_ceiling_rlusd=5000),
        compliance_reader=XrplLedgerComplianceReader(client),  # the point of today
    )


def main():
    state = load_state()

    # P1 - fund 5 accounts one at a time (resumable), then build the keystore.
    accounts = ["treasury", "exec_signer", "auditor_signer", "issuer", "unauth"]
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
    if not os.path.exists(KEYSTORE):
        ks = EncryptedKeystore.create(KEYSTORE)
        ks.add_seed("exec_signer", state["seeds"]["exec_signer"], state["exec_signer"], "ed25519")
        ks.add_seed("auditor_signer", state["seeds"]["auditor_signer"], state["auditor_signer"], "ed25519")
        ks.save()

    treasury = Wallet.from_seed(state["seeds"]["treasury"])
    issuer = Wallet.from_seed(state["seeds"]["issuer"])
    exec_w = Wallet.from_seed(state["seeds"]["exec_signer"])
    unauth = Wallet.from_seed(state["seeds"]["unauth"])

    # P2 - 2-of-2 SignerListSet on treasury (signed by master key, pre-disable).
    if not state.get("signer_list"):
        log("P2: SignerListSet (2-of-2) on treasury...")
        submit_single(SignerListSet(
            account=treasury.address, signer_quorum=2,
            signer_entries=[SignerEntry(account=state["exec_signer"], signer_weight=1),
                            SignerEntry(account=state["auditor_signer"], signer_weight=1)],
        ), treasury, "SignerListSet")
        state["signer_list"] = True
        save(state)

    # P3 - disable treasury master key (idempotent via flag check).
    if not state.get("master_disabled"):
        info = client.request(AccountInfo(account=treasury.address))
        if int(info.result["account_data"].get("Flags", 0)) & 0x00100000:
            log("P3: master already disabled.")
        else:
            log("P3: disabling treasury master key...")
            submit_single(AccountSet(account=treasury.address, set_flag=4), treasury, "AccountSet(disable master)")
        state["master_disabled"] = True
        save(state)

    # P4 - issuer creates the MPT issuance (RequireAuth + CanTransfer).
    if not state.get("issuance_id"):
        log("P4: issuer creates MPTokenIssuance (RequireAuth + CanTransfer)...")
        create = MPTokenIssuanceCreate(
            account=issuer.address,
            flags=MPTokenIssuanceCreateFlag.TF_MPT_REQUIRE_AUTH | MPTokenIssuanceCreateFlag.TF_MPT_CAN_TRANSFER,
            asset_scale=2, maximum_amount="1000000000", transfer_fee=0,
            mptoken_metadata=(b'{"ticker":"QVTB","name":"QuorumVault Test Bill",'b'"icon":"https://quorumvault.example/qvtb.png",'b'"asset_class":"rwa","issuer_name":"QuorumVault"}').hex().upper(),
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
        log(f"  issuance_id computed={computed} meta={meta_id}")
        state["issuance_id"] = meta_id or computed
        state["issuance_seq"] = seq
        save(state)

    iid = state["issuance_id"]

    # P5 - treasury opts in (multisig, since master is disabled).
    if not mptoken_exists(iid, treasury.address):
        log("P5: treasury opts in to the MPT (2-of-2 multisig)...")
        keystore = EncryptedKeystore.load(KEYSTORE)
        backends = [LocalEncryptedKeystoreBackend(keystore, "exec_signer"),
                    LocalEncryptedKeystoreBackend(keystore, "auditor_signer")]
        tx = MPTokenAuthorize(account=treasury.address, mptoken_issuance_id=iid)
        filled = autofill(tx, client, signers_count=2)
        combined = QuorumSigner(backends).multisign(filled)
        r = submit_and_wait(combined, client)
        log(f"  treasury opt-in: {r.result['meta']['TransactionResult']} ({r.result['hash']})")

    # P6 - issuer authorizes treasury.
    if not mptoken_authorized(iid, treasury.address):
        log("P6: issuer authorizes treasury...")
        submit_single(MPTokenAuthorize(account=issuer.address, mptoken_issuance_id=iid, holder=treasury.address),
                      issuer, "issuer authorize treasury")

    # P7 - issuer funds the treasury with an initial MPT balance.
    if not state.get("treasury_funded"):
        log("P7: issuer -> treasury MPT payment (initial balance)...")
        submit_single(Payment(account=issuer.address, destination=treasury.address,
                              amount=MPTAmount(mpt_issuance_id=iid, value="100000")), issuer, "issuer->treasury MPT")
        state["treasury_funded"] = True
        save(state)

    # P8 - exec_signer opts in.
    if not mptoken_exists(iid, exec_w.address):
        log("P8: exec_signer opts in...")
        submit_single(MPTokenAuthorize(account=exec_w.address, mptoken_issuance_id=iid), exec_w, "exec_signer opt-in")

    # P9 - issuer authorizes exec_signer (the compliant destination).
    if not mptoken_authorized(iid, exec_w.address):
        log("P9: issuer authorizes exec_signer...")
        submit_single(MPTokenAuthorize(account=issuer.address, mptoken_issuance_id=iid, holder=exec_w.address),
                      issuer, "issuer authorize exec_signer")

    # P10 - unauth opts in but is DELIBERATELY never issuer-authorized.
    if not mptoken_exists(iid, unauth.address):
        log("P10: unauth opts in (NO issuer authorization - the refused destination)...")
        submit_single(MPTokenAuthorize(account=unauth.address, mptoken_issuance_id=iid), unauth, "unauth opt-in")

    log(f"\nSetup complete. issuance_id={iid}")
    log(f"  exec_signer authorized: {mptoken_authorized(iid, exec_w.address)}")
    log(f"  unauth authorized:      {mptoken_authorized(iid, unauth.address)}")

    signer = build_signer(state)

    # P11 - COMPLIANT ceremony: treasury -> authorized exec_signer.
    if not state.get("compliant_hash"):
        log("\nP11: COMPLIANT ceremony (treasury -> authorized exec_signer) ...")
        pay = Payment(account=treasury.address, destination=exec_w.address,
                      amount=MPTAmount(mpt_issuance_id=iid, value="10"))
        out = run_ceremony(client, signer, pay, network="testnet", confirm=lambda p: True)
        log(f"  decision: tier={out['decision'].tier} risk={out['decision'].risk_level}")
        log(f"  RESULT: {out['status']}  HASH: {out['hash']}")
        state["compliant_hash"] = out["hash"]
        state["compliant_result"] = out["status"]
        save(state)

    # P12 - REFUSED ceremony: treasury -> never-authorized unauth (LIVE read).
    log("\nP12: REFUSED ceremony (treasury -> never-authorized account, live read) ...")
    pay = Payment(account=treasury.address, destination=unauth.address,
                  amount=MPTAmount(mpt_issuance_id=iid, value="10"))
    try:
        run_ceremony(client, signer, pay, network="testnet", confirm=lambda p: True)
        log("  ERROR: expected ExternalSignerRefused but the ceremony completed!")
        state["refused_ok"] = False
    except ExternalSignerRefused as e:
        log(f"  REFUSED as required: {e}")
        log(f"  decision: tier={signer.last_decision.tier} risk={signer.last_decision.risk_level} "
            f"reasons={signer.last_decision.fired_reasons}")
        state["refused_ok"] = True
        state["refused_reasons"] = signer.last_decision.fired_reasons
    save(state)

    log("\n==== SUMMARY ====")
    log(f"issuance_id      : {iid}")
    log(f"compliant tx     : {state.get('compliant_result')}  {state.get('compliant_hash')}")
    log(f"  explorer       : {EXPLORER}/{state.get('compliant_hash')}")
    log(f"refused path ok  : {state.get('refused_ok')}  reasons={state.get('refused_reasons')}")
    log("DONE")


if __name__ == "__main__":
    main()
