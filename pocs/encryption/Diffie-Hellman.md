# Diffie-Hellman Key Exchange

The Diffie-Hellman key exchange is the first public-key algorithm which appeared in the seminal paper by Diffie and Hellman that defined public-key cryptography [DIFF76]. Nowadays it underpins TLS, SSH, Signal, and most modern secure channels.

The purpose of the algorithm is to enable two users communicate over a channel that anyone can listen to by deriving a shared secret key securely that can then be used for subsequent encryption of message without ever sending that key.

The security of the Diffie-Hellman key exchange lies in the fact that,
while it is relatively easy to calculate exponentials modulo a prime, it is
very difficult to calculate discrete logarithms. For large primes, the latter
task is considered infeasible

## How it works

1. Alice and Bob publicly agree on two numbers: a large prime `q` and
   a generator `𝛼`. These can be public knowledge.
2. Alice picks a secret random number $X_{A}$ and computes
   $Y_{A} = 𝛼^{X_{A}}\mod\ q$. Bob picks a secret random number $X_{B}$ and computes
   $Y_{B} = 𝛼^{X_{B}}\mod\ q$.
3. Alice sends $Y_{A}$ to Bob, and Bob sends $Y_{B}$ to Alice, over the
   insecure channel.
4. Alice and Bob compute the exact same value due to the algebraic properties of modular exponentiation:


$$K_A = (Y_B)^{X_A} \bmod q = (\alpha^{X_B} \bmod q)^{X_A} \bmod q = \alpha^{X_B X_A} \bmod q$$

$$K_B = (Y_A)^{X_B} \bmod q = (\alpha^{X_A} \bmod q)^{X_B} \bmod q = \alpha^{X_A X_B} \bmod q$$

![](/assets/2026-09-12_19-27.png)

### Key Mathematical Requirements
- **Primitive Root ($\alpha$)**: The generator $\alpha$ should be a primitive root modulo $q$. This ensures that exponentiation generates all numbers in the multiplicative group $\mathbb{Z}_q^*$, maximizing the search space for an attacker trying to solve the discrete logarithm problem.
- **Safe Prime ($q$)**: To prevent attacks like the **Pohlig-Hellman algorithm**, $q$ should be a "safe prime" where **$q = 2p + 1$** and $p$ is also a prime. This ensures the group has no small prime factors.
- **Private Key Bounds**: The private values $X_A$ and $X_B$ must be chosen randomly from the range $[2, q-2]$ using a cryptographically secure random number generator (CSPRNG).

## Why an eavesdropper can't recover it

An attacker watching the exchange sees q, 𝛼, $Y_{A}$, and $Y_{B}$ — but
never $X_{A}$ or $X_{B}$. <br>
Thus, the adversary is forced to take a discrete logarithm to determine the key, which has no known efficient solution for **large
primes (2048 bits or more).**

## ⚠️ Important security notes

- **Plain Diffie-Hellman does not authenticate either party.** It
  protects against a passive eavesdropper, but not against an active
  attacker who intercepts and replaces both public keys
  (man-in-the-middle). Real protocols combine DH with digital
  signatures or certificates to prove identity.
- **The shared secret should never be used directly as an encryption
  key.** It should be passed through a KDF (e.g. HKDF) first.

## Running the demo

```bash
python diffie_hellman.py
```

The script first walks through the exchange with small, "by hand"
numbers so the math is easy to follow, then repeats the exact same
protocol with a real 2048-bit safe prime (RFC 3526, Group 14) to show
it at production scale.
