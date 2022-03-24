from typing import Tuple

Curve25519PrivateKey = bytes
Curve25519PublicKey  = bytes

Ed25519Seed = bytes
Ed25519PrivateKey = bytes
Ed25519PublicKey  = bytes

def crypto_sign_seed_keypair(seed: Ed25519Seed) -> Tuple[Ed25519PublicKey, Ed25519PrivateKey]: ...
def crypto_sign_ed25519_pk_to_curve25519(pk: Ed25519PublicKey) -> Curve25519PublicKey: ...
def crypto_sign_ed25519_sk_to_curve25519(sk: Ed25519PrivateKey) -> Curve25519PrivateKey: ...
