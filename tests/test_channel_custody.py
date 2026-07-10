"""Channel-Custody Lane: capacity is the audited exposure budget; claims are
off-ledger, un-audited, bounded, and monotonic."""

import pytest
from xrpl.core.binarycodec import encode_for_signing_claim
from xrpl.core.keypairs import is_valid_message
from xrpl.models.transactions import PaymentChannelClaim, PaymentChannelCreate

from quorumvault.signing.local_keystore import LocalEncryptedKeystoreBackend
from quorumvault.signing.quorum_signer import QuorumSigner
from quorumvault.tiers.channel_custody import ChannelCustodyLane, ChannelExposureError

TREASURY = "rUZjfJsZEQV6hQTX6mGBdD7BiD2jQ1rPce"
PAYEE = "rUJG3wx2DsbyCajtKSWKptTVsDLnevP63F"
CHANNEL_ID = "5DB01B7FFED6B67E6B0414DED11E051D2EE2B7619CE0EAA6286D67A3A4D5BDB3"


@pytest.fixture
def backends(keystore, passphrase):
    exec_b = LocalEncryptedKeystoreBackend(keystore, "exec_signer", passphrase)
    aud_b = LocalEncryptedKeystoreBackend(keystore, "auditor_signer", passphrase)
    return exec_b, aud_b


def test_open_rejects_capacity_over_cap(backends):
    exec_b, aud_b = backends
    lane = ChannelCustodyLane(capacity_cap_drops=1_000_000)
    with pytest.raises(ChannelExposureError):
        lane.open_channel(
            QuorumSigner([exec_b, aud_b]), TREASURY, exec_b, PAYEE,
            capacity_drops=2_000_000, settle_delay=86400, sequence=1, fee=20,
        )


def test_open_is_2of2_signed_channel_create(backends):
    exec_b, aud_b = backends
    lane = ChannelCustodyLane(capacity_cap_drops=5_000_000)
    signed, state = lane.open_channel(
        QuorumSigner([exec_b, aud_b]), TREASURY, exec_b, PAYEE,
        capacity_drops=1_000_000, settle_delay=86400, sequence=1, fee=20,
    )
    assert isinstance(signed, PaymentChannelCreate)
    assert len(signed.signers) == 2  # full quorum at open
    assert signed.amount == "1000000"
    assert state.capacity_drops == 1_000_000
    assert state.channel_public_key == exec_b.public_key


def test_open_audit_callback_can_veto(backends):
    exec_b, aud_b = backends
    lane = ChannelCustodyLane(capacity_cap_drops=5_000_000)
    with pytest.raises(ChannelExposureError):
        lane.open_channel(
            QuorumSigner([exec_b, aud_b]), TREASURY, exec_b, PAYEE,
            capacity_drops=1_000_000, settle_delay=86400, sequence=1, fee=20,
            audit=lambda ctx: False,
        )


def test_authorize_payment_produces_valid_offledger_signature(backends):
    exec_b, _ = backends
    lane = ChannelCustodyLane(capacity_cap_drops=5_000_000)
    state = _open_state(exec_b)

    sig = lane.authorize_payment(exec_b, state, cumulative_drops=250_000)
    blob = bytes.fromhex(
        encode_for_signing_claim({"channel": CHANNEL_ID, "amount": "250000"})
    )
    assert is_valid_message(blob, bytes.fromhex(sig), exec_b.public_key)
    assert state.authorized_drops == 250_000


def test_claims_are_bounded_and_monotonic(backends):
    exec_b, _ = backends
    lane = ChannelCustodyLane(capacity_cap_drops=5_000_000)
    state = _open_state(exec_b)

    lane.authorize_payment(exec_b, state, 250_000)
    lane.authorize_payment(exec_b, state, 500_000)  # increasing is fine
    with pytest.raises(ChannelExposureError):
        lane.authorize_payment(exec_b, state, 400_000)  # cannot go backwards
    with pytest.raises(ChannelExposureError):
        lane.authorize_payment(exec_b, state, 2_000_000)  # over capacity


def test_authorize_requires_matching_channel_key(backends):
    exec_b, aud_b = backends
    lane = ChannelCustodyLane(capacity_cap_drops=5_000_000)
    state = _open_state(exec_b)  # channel bound to exec_b's key
    with pytest.raises(ChannelExposureError):
        lane.authorize_payment(aud_b, state, 100_000)  # wrong key


def test_build_claim_is_auditable(backends):
    exec_b, _ = backends
    lane = ChannelCustodyLane(capacity_cap_drops=5_000_000)
    state = _open_state(exec_b)
    sig = lane.authorize_payment(exec_b, state, 300_000)

    claim = lane.build_claim(state, balance_drops=300_000, signature=sig, sequence=5, fee=20)
    assert isinstance(claim, PaymentChannelClaim)
    assert claim.balance == "300000"

    with pytest.raises(ChannelExposureError):
        lane.build_claim(
            state, 300_000, sig, sequence=6, fee=20, audit=lambda ctx: False
        )


def _open_state(channel_key):
    from quorumvault.tiers.channel_custody import ChannelState

    return ChannelState(
        payer=TREASURY,
        payee=PAYEE,
        capacity_drops=1_000_000,
        channel_public_key=channel_key.public_key,
        channel_id=CHANNEL_ID,
    )
