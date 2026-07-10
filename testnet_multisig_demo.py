"""
QuorumVault — Real XRPL Testnet 2-of-2 Multisig Proof
"""

import json
import os
import sys

from xrpl.clients import JsonRpcClient
from xrpl.wallet import generate_faucet_wallet, Wallet
from xrpl.models.transactions import SignerListSet, Payment, AccountSet
from xrpl.models.transactions.signer_list_set import SignerEntry as SignerEntryModel
from xrpl.transaction import autofill, sign, multisign, submit_and_wait
from xrpl.utils import xrp_to_drops

TESTNET_JSON_RPC = "https://s.altnet.rippletest.net:51234"
EXPLORER_TX_BASE = "https://testnet.xrpl.org/transactions"
WALLETS_FILE = "wallets_checkpoint.json"
STATE_FILE = "run_state.json"


def line(title):
    print("\n" + "=" * 70, flush=True)
    print(title, flush=True)
    print("=" * 70, flush=True)


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def main():
    client = JsonRpcClient(TESTNET_JSON_RPC)
    state = load_state()

    line("STEP 1 - Funding three Testnet accounts via faucet")
    if os.path.exists(WALLETS_FILE):
        with open(WALLETS_FILE) as f:
            w = json.load(f)
        treasury = Wallet.from_seed(w["treasury_seed"])
        exec_signer = Wallet.from_seed(w["exec_signer_seed"])
        auditor_signer = Wallet.from_seed(w["auditor_signer_seed"])
        print("Reusing previously funded wallets from checkpoint:", flush=True)
        print(f"treasury:       {treasury.address}", flush=True)
        print(f"exec_signer:    {exec_signer.address}", flush=True)
        print(f"auditor_signer: {auditor_signer.address}", flush=True)
    else:
        treasury = generate_faucet_wallet(client, debug=True)
        print(f"treasury:       {treasury.address}", flush=True)
        exec_signer = generate_faucet_wallet(client, debug=True)
        print(f"exec_signer:    {exec_signer.address}", flush=True)
        auditor_signer = generate_faucet_wallet(client, debug=True)
        print(f"auditor_signer: {auditor_signer.address}", flush=True)
        with open(WALLETS_FILE, "w") as f:
            json.dump({
                "treasury_seed": treasury.seed,
                "treasury_address": treasury.address,
                "exec_signer_seed": exec_signer.seed,
                "exec_signer_address": exec_signer.address,
                "auditor_signer_seed": auditor_signer.seed,
                "auditor_signer_address": auditor_signer.address,
            }, f, indent=2)
        print(f"Checkpointed wallets to {WALLETS_FILE}", flush=True)

    if state.get("signer_list_set_result") == "tesSUCCESS":
        line("STEP 2 - SKIPPED (already completed)")
        sls_hash = state["signer_list_set_tx_hash"]
        sls_final = state["signer_list_set_result"]
        print(f"SignerListSet tx hash: {sls_hash} ({sls_final})", flush=True)
    else:
        line("STEP 2 - Establishing 2-of-2 SignerListSet quorum on treasury")
        signer_list_tx = SignerListSet(
            account=treasury.address,
            signer_quorum=2,
            signer_entries=[
                SignerEntryModel(account=exec_signer.address, signer_weight=1),
                SignerEntryModel(account=auditor_signer.address, signer_weight=1),
            ],
        )
        signer_list_tx_filled = autofill(signer_list_tx, client)
        signer_list_tx_signed = sign(signer_list_tx_filled, treasury)
        signer_list_result = submit_and_wait(signer_list_tx_signed, client)
        sls_hash = signer_list_result.result["hash"]
        sls_final = signer_list_result.result["meta"]["TransactionResult"]
        print(f"SignerListSet tx hash: {sls_hash}", flush=True)
        print(f"SignerListSet result:  {sls_final}", flush=True)
        state["signer_list_set_tx_hash"] = sls_hash
        state["signer_list_set_result"] = sls_final
        save_state(state)
        if sls_final != "tesSUCCESS":
            print("SignerListSet did not succeed - aborting.", flush=True)
            sys.exit(1)

    if state.get("disable_master_key_result") == "tesSUCCESS":
        line("STEP 3 - SKIPPED (already completed)")
        dm_hash = state["disable_master_key_tx_hash"]
        dm_final = state["disable_master_key_result"]
        print(f"AccountSet tx hash: {dm_hash} ({dm_final})", flush=True)
    else:
        line("STEP 3 - Disabling treasury's master key")
        disable_master_tx = AccountSet(account=treasury.address, set_flag=4)
        disable_master_filled = autofill(disable_master_tx, client)
        disable_master_signed = sign(disable_master_filled, treasury)
        disable_master_result = submit_and_wait(disable_master_signed, client)
        dm_hash = disable_master_result.result["hash"]
        dm_final = disable_master_result.result["meta"]["TransactionResult"]
        print(f"AccountSet tx hash: {dm_hash}", flush=True)
        print(f"AccountSet result:  {dm_final}", flush=True)
        state["disable_master_key_tx_hash"] = dm_hash
        state["disable_master_key_result"] = dm_final
        save_state(state)

    if state.get("multisig_payment_result"):
        line("STEP 4/5 - SKIPPED (already completed)")
        pay_hash = state["multisig_payment_tx_hash"]
        pay_final = state["multisig_payment_result"]
        print(f"Payment tx hash: {pay_hash} ({pay_final})", flush=True)
    else:
        line("STEP 4 - Building the multisigned Payment")
        payment_tx = Payment(
            account=treasury.address,
            amount=xrp_to_drops(1),
            destination=exec_signer.address,
        )
        payment_tx_filled = autofill(payment_tx, client, signers_count=2)
        print("Signing with exec_signer (Signature_1)...", flush=True)
        payment_signed_1 = sign(payment_tx_filled, exec_signer, multisign=True)
        print("Signing with auditor_signer (Signature_2)...", flush=True)
        payment_signed_2 = sign(payment_tx_filled, auditor_signer, multisign=True)
        print("Combining signatures...", flush=True)
        combined_tx = multisign(payment_tx_filled, [payment_signed_1, payment_signed_2])

        line("STEP 5 - Submitting the multisigned Payment to XRPL Testnet")
        payment_result = submit_and_wait(combined_tx, client)
        pay_hash = payment_result.result["hash"]
        pay_final = payment_result.result["meta"]["TransactionResult"]
        print(f"Payment tx hash: {pay_hash}", flush=True)
        print(f"Payment result:  {pay_final}", flush=True)
        state["multisig_payment_tx_hash"] = pay_hash
        state["multisig_payment_result"] = pay_final
        save_state(state)

    line("SUMMARY")
    summary = {
        "treasury_address": treasury.address,
        "exec_signer_address": exec_signer.address,
        "auditor_signer_address": auditor_signer.address,
        "signer_list_set_tx_hash": state.get("signer_list_set_tx_hash"),
        "signer_list_set_result": state.get("signer_list_set_result"),
        "disable_master_key_tx_hash": state.get("disable_master_key_tx_hash"),
        "disable_master_key_result": state.get("disable_master_key_result"),
        "multisig_payment_tx_hash": state.get("multisig_payment_tx_hash"),
        "multisig_payment_result": state.get("multisig_payment_result"),
        "explorer_link": f"{EXPLORER_TX_BASE}/{state.get('multisig_payment_tx_hash')}",
    }
    print(json.dumps(summary, indent=2), flush=True)
    with open("testnet_multisig_result.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nWrote testnet_multisig_result.json", flush=True)


if __name__ == "__main__":
    main()
