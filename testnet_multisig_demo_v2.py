"""QuorumVault v2 demo — the proven 2-of-2 flow, now on the signing abstraction.

This is the refactor of ``testnet_multisig_demo.py``. The original is kept intact
as the historical proof. The two differences that matter:

1. **No plaintext seeds.** Signers are loaded from the encrypted keystore via
   ``LocalEncryptedKeystoreBackend`` (passphrase from ``QUORUMVAULT_KEYSTORE_PASSPHRASE``),
   not from ``wallets_checkpoint.json``. Migrate first with
   ``python -m quorumvault.tools.migrate_keystore``.
2. **Signing goes through ``QuorumSigner``**, so the same code path works whether
   the keys live in the local keystore or an HSM/KMS — the auditor/quorum logic
   above is unchanged.

**Safety:** the default is a fully offline dry run — it builds and multisigns
transactions in memory and makes no network calls and moves no funds. Live
submission is opt-in via ``--submit`` and targets **XRPL Testnet only**. Nothing
here can touch Mainnet.
"""

from __future__ import annotations

import argparse
import os
import sys

from xrpl.models.transactions import Payment

from quorumvault.policy.intent import PaymentIntent, RwaTransfer
from quorumvault.signing.keystore import EncryptedKeystore
from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.config import default_settings, load_settings

TESTNET_JSON_RPC = "https://s.altnet.rippletest.net:51234"


def line(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def load_backends(keystore_path: str):
    if not os.path.exists(keystore_path):
        print(
            f"No keystore at {keystore_path!r}. Create it from your checkpoint with:\n"
            "  export QUORUMVAULT_KEYSTORE_PASSPHRASE=...\n"
            "  python -m quorumvault.tools.migrate_keystore --shred",
            file=sys.stderr,
        )
        raise SystemExit(2)
    keystore = EncryptedKeystore.load(keystore_path)
    exec_backend = LocalEncryptedKeystoreBackend(keystore, "exec_signer")
    auditor_backend = LocalEncryptedKeystoreBackend(keystore, "auditor_signer")
    return exec_backend, auditor_backend


def demo_routing(router) -> None:
    line("TIER ROUTING (offline) — the transaction's stakes pick the lane")
    samples = [
        PaymentIntent(destination="rPayee...", asset="XRP", amount=5, purpose="API call"),
        PaymentIntent(destination="rVendor...", asset="RLUSD", amount=1500, purpose="invoice"),
        PaymentIntent(destination="rBank...", asset="RLUSD", amount=250000, purpose="treasury sweep"),
        PaymentIntent(
            destination="rFund...", asset="RLUSD", amount=10, purpose="tokenized T-bill",
            rwa=RwaTransfer(requires_authorization=True, destination_authorized=False),
        ),
    ]
    for intent in samples:
        decision = router.route(intent)
        print(
            f"  {intent.amount:>8,.0f} {intent.asset:<6} {intent.purpose:<20} -> "
            f"{decision.tier.value:<16} ({', '.join(decision.reasons)})"
        )


def demo_offline_multisign(exec_backend, auditor_backend) -> None:
    line("2-of-2 QUORUM (offline) — multisign a Payment via the abstraction")
    treasury = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"  # from the proven Testnet run
    payment = Payment(
        account=treasury,
        amount="1000000",  # 1 XRP in drops
        destination=exec_backend.classic_address,
        sequence=1,
        fee="20",
        signing_pub_key="",
        last_ledger_sequence=100_000,
    )
    signed = QuorumSigner([exec_backend, auditor_backend]).multisign(payment)
    print(f"  signers on tx: {[s.account for s in signed.signers]}")
    print(f"  both signatures present: {len(signed.signers) == 2}")
    print("  (built and signed in memory — no network, no funds moved)")


def run_live_testnet(exec_backend, auditor_backend) -> None:
    """Opt-in: submit ONE multisigned Payment to XRPL Testnet. Testnet only."""
    from xrpl.clients import JsonRpcClient
    from xrpl.transaction import autofill, submit_and_wait
    from xrpl.utils import xrp_to_drops

    line("LIVE TESTNET SUBMIT — multisigned Payment (Testnet only)")
    client = JsonRpcClient(TESTNET_JSON_RPC)
    treasury = os.environ.get("QUORUMVAULT_TREASURY_ADDRESS")
    if not treasury:
        print("Set QUORUMVAULT_TREASURY_ADDRESS to the treasury account.", file=sys.stderr)
        raise SystemExit(2)

    payment = Payment(
        account=treasury,
        amount=xrp_to_drops(1),
        destination=exec_backend.classic_address,
    )
    filled = autofill(payment, client, signers_count=2)
    signed = QuorumSigner([exec_backend, auditor_backend]).multisign(filled)
    result = submit_and_wait(signed, client)
    print(f"  tx hash: {result.result['hash']}")
    print(f"  result:  {result.result['meta']['TransactionResult']}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keystore", default="keystore.json")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to a risk & routing settings JSON file (see "
        "config.example.json). If omitted, the built-in default_settings() are "
        "used - the same values as before.",
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        help="Broadcast one multisigned Payment to XRPL Testnet (opt-in, Testnet only).",
    )
    args = parser.parse_args(argv)

    # Risk & routing parameters now come from a settings object: a config file
    # if one is given, else the built-in defaults (same 100/5000 ceilings as
    # before). This replaces the previously hardcoded TierRouter(...) call.
    settings = load_settings(args.config) if args.config else default_settings()

    exec_backend, auditor_backend = load_backends(args.keystore)
    demo_routing(settings.build_router())
    demo_offline_multisign(exec_backend, auditor_backend)

    if args.submit:
        confirm = os.environ.get("QUORUMVAULT_CONFIRM_TESTNET") == "yes"
        if not confirm:
            print(
                "\nRefusing to submit: set QUORUMVAULT_CONFIRM_TESTNET=yes to confirm "
                "a live XRPL Testnet broadcast.",
                file=sys.stderr,
            )
            return 2
        run_live_testnet(exec_backend, auditor_backend)
    else:
        print("\nDry run complete. No network calls were made. Re-run with --submit "
              "(Testnet only) to broadcast.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
