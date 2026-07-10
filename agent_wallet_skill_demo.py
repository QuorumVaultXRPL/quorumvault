"""Live Testnet demo: QuorumVault as the XRPL Agent Wallet Skill's ExternalSigner.

The skill refuses multisig ("the developer needs a dedicated multisig flow").
This demo bootstraps a fresh Testnet 2-of-2 treasury (faucet -> SignerListSet ->
disable master key), stores the two signer seeds in an encrypted keystore, and
then runs the skill's documented six-step ceremony -- autofill, the exact preview
block, confirm, sign, persist-hash, submitAndWait -- with QuorumVault standing in
as the ExternalSigner. The "sign" step is a full risk-gated 2-of-2 multisig,
invisible to the ceremony.

Testnet only. Resumable via a local state file so reruns skip completed setup.
"""

from __future__ import annotations

import json
import os
import sys
import time

from xrpl.clients import JsonRpcClient
from xrpl.models.transactions import AccountSet, Payment, SignerListSet
from xrpl.models.transactions.signer_list_set import SignerEntry
from xrpl.transaction import autofill, sign, submit_and_wait
from xrpl.utils import xrp_to_drops
from xrpl.wallet import Wallet, generate_faucet_wallet

from quorumvault.integrations.agent_wallet_ceremony import run_ceremony
from quorumvault.integrations.external_signer import QuorumVaultExternalSigner
from quorumvault.policy.risk_engine import RiskEngine
from quorumvault.signing.keystore import EncryptedKeystore
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.tiers.router import TierRouter

TESTNET = "https://s.altnet.rippletest.net:51234"
EXPLORER = "https://testnet.xrpl.org/transactions"
STATE = os.environ.get("AGENT_DEMO_STATE", "/tmp/agent_wallet_demo_state.json")
KEYSTORE = os.environ.get("AGENT_DEMO_KEYSTORE", "/tmp/agent_wallet_demo_keystore.json")
os.environ.setdefault("QUORUMVAULT_KEYSTORE_PASSPHRASE", "agent-wallet-demo-passphrase")


def log(msg):
    print(msg, flush=True)


def load_state():
    return json.load(open(STATE)) if os.path.exists(STATE) else {}


def save_state(s):
    json.dump(s, open(STATE, "w"), indent=2)


def main():
    client = JsonRpcClient(TESTNET)
    state = load_state()

    # -- Phase 1: fund treasury + two signer accounts -----------------------
    if "treasury_seed" not in state:
        log("PHASE 1: funding treasury + 2 signer accounts via Testnet faucet...")
        treasury = generate_faucet_wallet(client, debug=False)
        exec_signer = generate_faucet_wallet(client, debug=False)
        auditor_signer = generate_faucet_wallet(client, debug=False)
        # Signer seeds go into an ENCRYPTED keystore, never plaintext state.
        ks = EncryptedKeystore.create(KEYSTORE)
        ks.add_seed("exec_signer", exec_signer.seed, exec_signer.address, "ed25519")
        ks.add_seed("auditor_signer", auditor_signer.seed, auditor_signer.address, "ed25519")
        ks.save()
        # The treasury's master key is disabled below, so its seed is worthless
        # afterwards; kept in state only to resume setup.
        state.update(
            treasury_seed=treasury.seed,
            treasury=treasury.address,
            exec_signer=exec_signer.address,
            auditor_signer=auditor_signer.address,
        )
        save_state(state)
        log(f"  treasury={treasury.address} exec={exec_signer.address} auditor={auditor_signer.address}")
    treasury = Wallet.from_seed(state["treasury_seed"])

    # -- Phase 2: 2-of-2 SignerListSet on the treasury ----------------------
    if not state.get("signer_list_done"):
        log("PHASE 2: SignerListSet (2-of-2 quorum) on treasury...")
        tx = SignerListSet(
            account=treasury.address,
            signer_quorum=2,
            signer_entries=[
                SignerEntry(account=state["exec_signer"], signer_weight=1),
                SignerEntry(account=state["auditor_signer"], signer_weight=1),
            ],
        )
        r = submit_and_wait(sign(autofill(tx, client), treasury), client)
        code = r.result["meta"]["TransactionResult"]
        log(f"  SignerListSet: {code} ({r.result['hash']})")
        if code != "tesSUCCESS":
            sys.exit(f"SignerListSet failed: {code}")
        state["signer_list_done"] = True
        save_state(state)

    # -- Phase 3: disable the treasury master key ---------------------------
    if not state.get("master_disabled"):
        from xrpl.models.requests import AccountInfo
        info = client.request(AccountInfo(account=treasury.address))
        already = bool(int(info.result["account_data"].get("Flags", 0)) & 0x00100000)  # lsfDisableMaster
        if already:
            log("PHASE 3: treasury master key already disabled; skipping.")
        else:
            log("PHASE 3: disabling treasury master key (multisig becomes the only path)...")
            tx = AccountSet(account=treasury.address, set_flag=4)  # asfDisableMasterKey
            r = submit_and_wait(sign(autofill(tx, client), treasury), client)
            code = r.result["meta"]["TransactionResult"]
            log(f"  AccountSet(disable master): {code} ({r.result['hash']})")
            if code != "tesSUCCESS":
                sys.exit(f"disable master failed: {code}")
        state["master_disabled"] = True
        save_state(state)

    # -- Phase 4: the ceremony, with QuorumVault as ExternalSigner ----------
    log("PHASE 4: running the Agent Wallet Skill ceremony via QuorumVault ExternalSigner...")
    keystore = EncryptedKeystore.load(KEYSTORE)
    backends = [
        LocalEncryptedKeystoreBackend(keystore, "exec_signer"),
        LocalEncryptedKeystoreBackend(keystore, "auditor_signer"),
    ]
    destination = state["exec_signer"]  # a real funded account, distinct from treasury
    signer = QuorumVaultExternalSigner(
        treasury_address=treasury.address,
        quorum_signer=QuorumSigner(backends),
        risk_engine=RiskEngine(whitelist=[destination], amount_threshold_rlusd=5000, frequency_limit=20),
        # Ceilings set low so this treasury transfer routes to the 2-of-2 backstop.
        router=TierRouter(channel_ceiling_rlusd=1, fast_path_ceiling_rlusd=2),
    )

    payment = Payment(account=treasury.address, amount=xrp_to_drops(5), destination=destination)
    outcome = run_ceremony(client, signer, payment, network="testnet", confirm=lambda preview: True)

    log("")
    log(f"AUDITOR DECISION (invisible to the ceremony): tier={outcome['decision'].tier}, "
        f"risk={outcome['decision'].risk_level}")
    log(f"RESULT: {outcome['status']}")
    log(f"TX HASH: {outcome['hash']}")
    log(f"EXPLORER: {EXPLORER}/{outcome['hash']}")
    state["ceremony_hash"] = outcome["hash"]
    state["ceremony_result"] = outcome["status"]
    save_state(state)
    log("DONE")


if __name__ == "__main__":
    main()
