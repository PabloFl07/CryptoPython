"""
Proof of Concept: Diffie-Hellman Key Exchange
================================================

Demonstrates how two parties (Alice and Bob) can agree on a shared
secret over a channel that anyone can listen to, without ever
transmitting the secret itself.

Educational purposes only — see README.md for the theory and
important security caveats (e.g. this alone does not authenticate
either party).
"""

import secrets

# --- RFC 3526 MODP Group 14 (2048-bit safe prime) ---
# The same kind of parameter real protocols (IKE/IPsec, SSH) use for
# production-grade Diffie-Hellman exchanges.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD"
    "129024E088A67CC74020BBEA63B139B22514A08798E3404"
    "DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C"
    "245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406"
    "B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE"
    "45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD"
    "24CF5F83655D23DCA3AD961C62F356208552BB9ED529077"
    "096966D670C354E4ABC9804F1746C08CA18217C32905E46"
    "2E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF"
    "06F4C52C9DE2BCBF6955817183995497CEA956AE515D226"
    "1898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2  # generator


class DHParticipant:
    """One side of a Diffie-Hellman exchange (e.g. Alice or Bob)."""

    def __init__(self, name: str, large_prime: int = P, generator: int = G):
        self.name = name
        self.p = large_prime
        self.g = generator
        # Private key: a random number, never shared with anyone.
        self.private_key = secrets.randbelow(large_prime - 2) + 2
        # Public key: g^private mod p. Safe to send over an insecure channel.
        self.public_key = pow(self.g, self.private_key, self.p)
        self.shared_secret = None

    def compute_shared_secret(self, other_public_key: int) -> int:
        """Combine our private key with the other party's public key."""
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        return self.shared_secret


def small_number_demo():
    """Walks through the math with tiny numbers so it's easy to follow by hand."""
    print("=" * 60)
    print("PART 1 - The math, with small numbers")
    print("=" * 60)

    large_prime, generator = 23, 5  # NOT secure - illustration only
    print(f"Public parameters (known to everyone, even an attacker): p={large_prime}, g={generator}\n")

    a = secrets.randbelow(large_prime - 2) + 2  # Alice's private key
    b = secrets.randbelow(large_prime - 2) + 2  # Bob's private key
    print(f"Alice picks a private number:  a = {a}")
    print(f"Bob picks a private number:    b = {b}\n")

    A = pow(generator, a, large_prime)  # Alice's public key
    B = pow(generator, b, large_prime)  # Bob's public key
    print(f"Alice computes A = g^a mod p = {A}  --> sends A to Bob")
    print(f"Bob computes   B = g^b mod p = {B}  --> sends B to Alice\n")

    alice_secret = pow(B, a, large_prime)
    bob_secret = pow(A, b, large_prime)
    print(f"Alice computes B^a mod p = {alice_secret}")
    print(f"Bob computes   A^b mod p = {bob_secret}")
    print(f"\nBoth arrive at the same secret: {alice_secret == bob_secret}")
    print("An eavesdropper who only saw p, g, A and B cannot easily recover")
    print("this shared secret without solving the discrete logarithm problem.\n")


def real_world_demo():
    """Same protocol, but with a cryptographically-sized safe prime."""
    print("=" * 60)
    print("PART 2 - The same protocol with real-world parameters")
    print("=" * 60)

    alice = DHParticipant("Alice")
    bob = DHParticipant("Bob")

    print(f"Alice's public key (truncated): {hex(alice.public_key)[:40]}...")
    print(f"Bob's public key   (truncated): {hex(bob.public_key)[:40]}...\n")

    alice_secret = alice.compute_shared_secret(bob.public_key)
    bob_secret = bob.compute_shared_secret(alice.public_key)

    print(f"Shared secrets match: {alice_secret == bob_secret} ")
    print(f"Shared secret (truncated): {hex(alice_secret)[:40]}...\n")
    print("In practice this shared secret is fed into a KDF (e.g. HKDF) to")
    print("derive an actual AES key - it should never be used directly as one.")


if __name__ == "__main__":
    small_number_demo()
    real_world_demo()