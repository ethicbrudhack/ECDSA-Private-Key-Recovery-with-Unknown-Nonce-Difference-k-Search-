# 🧩 ECDSA Private Key Recovery with Unknown Nonce Difference (Δk Search)

This Python script demonstrates a **brute-force search for the nonce difference (Δk)** between two ECDSA signatures created with the same private key on the **secp256k1** curve (used in Bitcoin).  
It attempts to recover the **private key** by scanning a range of possible `Δk` values and verifying candidate solutions against a known **Bech32 Bitcoin address**.

---

## ⚙️ What the script does

1. Takes two known **ECDSA signatures** (`r1, s1, z1`) and (`r2, s2, z2`) created with the same private key.
2. Computes **initial estimates** of the nonce difference `Δk` using proportional relationships between the signature parameters.
3. Iterates through a search window (±10,000 by default) around those estimates.
4. For each candidate `Δk`, the script:
   - Computes a potential private key `d` via the ECDSA equation:
     \[
     d = [Δk ⋅ s₁ ⋅ s₂ − (s₂z₁ − s₁z₂)] ⋅ (s₂r₁ − s₁r₂)^{-1} \mod n
     \]
   - Derives the **compressed public key** from `d`.
   - Generates the **Bech32 address** from the public key.
   - Compares the result with a **known target address**.
5. Stops when a match is found and displays the recovered private key and public data.

---

## 🧠 Mathematical background

ECDSA signatures rely on a unique random number `k` (the nonce) per message:

\[
s = k^{-1} (z + d ⋅ r) \mod n
\]

If two signatures reuse related nonces, such that:

\[
k₁ - k₂ = Δk
\]

then algebraic manipulation allows computation of the private key `d`, **if Δk is known or can be guessed**.

This script automates the process of **guessing Δk** and verifying results via address reconstruction.

---

## 🧮 Key functions

| Function | Purpose |
|-----------|----------|
| `modinv(a, n)` | Modular inverse via Extended Euclidean Algorithm |
| `compute_private_key(...)` | Computes `d` using the Δk-based recovery equation |
| `private_key_to_compressed_pubkey(d)` | Derives a compressed public key from the private key |
| `pubkey_to_bech32(pubkey_hex)` | Generates a Bech32 (SegWit) Bitcoin address from the public key |

---

## 🧩 Example data

The script includes example parameters extracted from two valid ECDSA signatures:

```python
r1, r2, s1, s2, z1, z2 = (signature values)
target_address = "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h"
You can adjust:

The search window (scan_range)

The step size (step)

The curve parameters (n for secp256k1 or others)

The known address to match against

🚀 How to use

Install dependencies:

pip install ecdsa bech32


Run the script:

python3 recover_private_key_deltak_scan.py


The script will print progress updates:

🔍 Początkowe delta_k1: ...
🔍 Początkowe delta_k2: ...
⏳ Test offset 0... address: bc1q...
...
✅ ZNALEZIONO!
🔑 Prywatny klucz (hex): 0x...
📬 Publiczny klucz: 02...
🏠 Adres: bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h


If the correct Δk lies within the tested range, the matching private key will be found.

🧠 When it works

This attack only works when:

Two ECDSA signatures were created using the same private key.

Their ephemeral nonces differ by a small or partially known value Δk.

You have access to both signature pairs (r, s, z).

The underlying curve order n (e.g. secp256k1) is known.

In realistic scenarios, this can happen due to:

Weak or deterministic RNG used to generate k,

Implementation bugs causing nonce reuse,

Hardware RNG leakage or synchronization issues.

⚠️ Security & ethical notice

⚠️ For educational and research purposes only.

Do not use this code to attempt to recover private keys without explicit authorization.

Always use synthetic, testnet, or lab-generated data.

The script demonstrates a real-world ECDSA vulnerability caused by nonce correlation.

If you discover such a vulnerability in production software, report it responsibly.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
