---
title: "Why ECB Mode Leaks Structure: A Byte-at-a-Time Oracle"
description: "How a local AES-128-ECB oracle gives up a 30-byte secret one byte at a time, why ECB leaks block equality, and what to use instead."
type: blog
blog_type: analysis
tags:
  - cryptography
  - aes
  - ecb
  - python
---

AES-ECB encrypts each 16-byte block on its own, so equal plaintext blocks become equal ciphertext blocks under the same key. An attacker who can submit chosen input and read the ciphertext can use that equality to recover a secret without attacking AES itself.

This post rebuilds the classic byte-at-a-time attack ([Cryptopals Set 2, Challenge 12](https://cryptopals.com/sets/2/challenges/12)) against a local AES-128-ECB oracle. The solver recovers a 30-byte secret in 761 queries. It never sees the key: it compares ciphertext blocks and keeps the candidate that produces a match.

## The property that breaks it

ECB is a mode of operation; AES is the cipher. FIPS 197 defines AES, and NIST SP 800-38A defines ECB along with the other classic confidentiality modes. Under ECB, each block is encrypted independently:

```text
C[i] = E(K, P[i])
```

There is no chaining value, no initialization vector, and no per-message state, so nothing varies from one block to the next. Identical plaintext blocks therefore produce identical ciphertext blocks. Encrypting 32 bytes of `A` followed by 16 bytes of `B` under AES-128 with the key `00 01 02 ... 0f` shows it:

```text
block 0  AAAAAAAAAAAAAAAA  ->  dd4b1a0b47daa7067d0b59d95d58a6ae
block 1  AAAAAAAAAAAAAAAA  ->  dd4b1a0b47daa7067d0b59d95d58a6ae
block 2  BBBBBBBBBBBBBBBB  ->  87f815ad0e513346e0afe99814b1a504
```

Anyone who sees those ciphertext blocks can tell that the first two plaintext blocks were equal, without the key and without knowing what they contained. The `show_equality()` function in the complete script at the end of this post prints this listing.

This is the same property behind the well-known ECB penguin: large runs of a single color in an image survive encryption as repeated ciphertext blocks, so the outline stays visible. ECB hides the contents of each block, but the pattern between blocks remains visible.

## A local oracle

The demo needs Python 3.9 or later and the `cryptography` package. The oracle uses a fixed key and a fixed 30-byte secret, and it puts the attacker's input in front of the secret, so the input can shift the secret across block boundaries.

```python
import string

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(16))
SECRET = b"demo{ecb_mode_leaks_structure}"
ALPHABET = (string.ascii_letters + string.digits + string.punctuation + " ").encode()
queries = 0


def ecb_encrypt(plaintext: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def oracle(prefix: bytes) -> bytes:
    global queries
    queries += 1
    padder = padding.PKCS7(128).padder()
    return ecb_encrypt(padder.update(prefix + SECRET) + padder.finalize())


def blocks(data: bytes, size: int) -> list[bytes]:
    return [data[i:i + size] for i in range(0, len(data), size)]
```

The key stays inside `ecb_encrypt` and `oracle`. The solver functions below call only `oracle` and `blocks`. The oracle appends the secret to whatever prefix it receives and applies PKCS#7 padding, so the ciphertext length grows in whole-block steps as the prefix grows. The next step uses exactly that.

I fixed the key so the ciphertext values in this post are reproducible. The attack never needs it, and the query counts do not depend on it.

## Measure the block size and the secret length

The ciphertext grows in block-sized steps. Send one more filler byte at a time until the length jumps; the size of the jump is the block size. At the jump, the filler plus the secret fill a whole number of blocks exactly, and PKCS#7 adds one extra block of padding. The ciphertext length is therefore `n + secret_len + block_size`, which gives the secret length:

```python
def measure_parameters() -> tuple[int, int]:
    previous = len(oracle(b""))
    for n in range(1, 65):
        current = len(oracle(b"A" * n))
        if current > previous:
            block_size = current - previous
            secret_len = current - block_size - n
            return block_size, secret_len
        previous = current
    raise RuntimeError("no length change observed")
```

With a 30-byte secret, an empty input pads to 32 bytes, and so does one filler byte. Two filler bytes make 32 bytes of plaintext, PKCS#7 adds a full block, and the ciphertext jumps from 32 to 48 bytes:

```text
n = 2: 48 - 16 - 2 = 30
```

If the secret were block-aligned, the first jump would come later, at `n = 16`, and the same formula would still apply.

```text
block size: 16
secret length: 30 bytes
```

## Recover one byte at a time

At offset `i`, use `n = (16 - 1 - i) % 16` filler bytes. That puts the unknown byte at the last position of block `(n + i) // 16`.

For the first byte, `i = 0` and `n = 15`: the oracle encrypts 15 `A` bytes followed by the secret, so block 0 holds the 15 `A` bytes plus the first secret byte. For the second byte, `i = 1` and `n = 14`: block 0 holds 14 `A` bytes, the first recovered byte, and the second, still unknown byte.

The solver gets the target block from a query that contains only filler, which leaves the unknown byte at the end of the block. It then sends the filler, the bytes recovered so far, and one candidate byte. When the candidate is correct, the two 16-byte blocks are identical.

```python
def recover_secret(block_size: int, secret_len: int) -> bytes:
    recovered = b""
    for i in range(secret_len):
        n = (block_size - 1 - i) % block_size
        index = (n + i) // block_size
        target = blocks(oracle(b"A" * n), block_size)[index]
        for candidate in ALPHABET:
            probe = oracle(b"A" * n + recovered + bytes([candidate]))
            if blocks(probe, block_size)[index] == target:
                recovered += bytes([candidate])
                break
        else:
            raise RuntimeError(f"no candidate matched at offset {i}")
    return recovered
```

The alignment for the first few offsets looks like this:

| Offset `i` | Filler `n` | Block index | Position in block | Position in ciphertext |
|---:|---:|---:|---:|---:|
| 0 | 15 | 0 | 15 | 15 |
| 1 | 14 | 0 | 15 | 15 |
| 15 | 0 | 0 | 15 | 15 |
| 16 | 15 | 1 | 15 | 31 |

The unknown byte is always the last byte of its block; only the block index changes. The comparison is a plain equality test. The solver never decrypts anything, and the key stays inside the oracle.

## The run

```text
block size: 16
secret length: 30 bytes
recovered: b'demo{ecb_mode_leaks_structure}'
queries: 761
```

The 761 queries break down as 3 to measure the parameters, 30 target queries (one per byte), and 728 candidate probes, about 24 per byte.

The cost depends on the candidate list and, just as much, on its order. I used the 95 printable ASCII characters in the order Python's `string` module lists them: lowercase letters, uppercase letters, digits, punctuation, then space. A lowercase `a` costs one probe, while the closing `}` is the 93rd candidate. If every byte were the last candidate, the run would take 2,883 queries; if every byte were the first, 63. Both figures include the 3 measuring queries.

A binary secret needs all 256 byte values. I ran the same solver with `bytes(range(256))` as the candidate list, and it took 3,273 queries for this secret. That figure depends on the secret and on the candidate order, but the loop itself does not change.

## What the attack needs

The attack has three requirements:

- **Chosen input next to the secret.** The attacker controls bytes that land immediately before the secret, so the secret can be slid across a block boundary. A single captured ciphertext is not enough.
- **Determinism.** The same key, mode, and input must give the same ciphertext.
- **A stable alignment.** The secret's position relative to the attacker's input must not change between queries. A prefix of constant length only shifts the alignment by a fixed amount, which the attacker can compensate for. A prefix whose length varies from request to request moves the block boundaries, so the target block changes between queries and the simple comparison stops working; the attacker would have to find a stable alignment first. I did not build either variant.

What comes out is the plaintext exactly as the oracle encrypts it. If an application compresses or encodes the secret before encryption, the attacker recovers that encoded form.

The attack does not recover the AES key, and it does not work against a correctly used AEAD, which produces different ciphertext for the same input because every message gets a fresh nonce. It recovers plaintext from a mode that leaks block equality.

## What else ECB's design allows

Equality leakage is one consequence of encrypting blocks independently; malleability is another. Because each block stands alone and nothing authenticates the message as a whole, an attacker can reorder, repeat, drop, or splice blocks, including blocks taken from other messages, without triggering any integrity failure. The byte-at-a-time oracle turns the equality leak into full plaintext recovery with a short script.

## Why ECB keeps showing up

ECB is simple, parallelizable, and needs no IV, which is why it survives in legacy storage and embedded code. It also arrives through defaults. In MySQL 8.0, the `block_encryption_mode` setting defaults to `aes-128-ecb` ([MySQL Secure Deployment Guide](https://dev.mysql.com/doc/mysql-secure-deployment-guide/8.0/en/secure-deployment-block-encryption-mode.html)). In Java, a transformation such as `Cipher.getInstance("AES")` leaves the mode and padding to the provider. Oracle's JDK documentation says that SunJCE and SunPKCS11 fall back to ECB and PKCS5Padding for many symmetric ciphers when a transformation omits them, and it recommends spelling out the full transformation ([JDK Providers Documentation](https://docs.oracle.com/pls/topic/lookup?ctx=javase12&id=security_guide_jdk_providers)). OWASP's Java guidance warns about the same thing for AES: specify the mode explicitly, because most JCE providers default to ECB ([OWASP](https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions)). Defaults like these put ECB into code that never chose it.

The failure is in the mode, not the cipher: AES-128 in ECB mode is still AES. ECB adds no variation from block to block (no IV, nonce, or chaining), so equal inputs map to equal outputs. A longer key does not change that.

## What to use instead

For new designs, use an AEAD such as AES-GCM ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)) or ChaCha20-Poly1305 ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)). Both provide confidentiality and integrity, and both require a unique nonce for every message under a given key. Reusing a nonce under the same key breaks them.

If the design really needs deterministic ciphertexts, for example to look up encrypted values by equality, use a dedicated deterministic AEAD such as AES-SIV ([RFC 5297](https://www.rfc-editor.org/rfc/rfc5297)) and document the equality leak that remains. Do not invent a mode, and do not add a fixed IV to CBC and call it deterministic.

For existing code, find the ECB usage and replace the construction. Rotating the key does not fix a mode that leaks block equality.

## Checks that catch the mistake

- **Encrypt the same plaintext twice.** Identical ciphertexts mean the encryption is deterministic. That can be intentional, but it needs a documented reason. Where the design expects randomized encryption, make this a test that fails when the two ciphertexts match.
- **Encrypt a run of at least 48 identical bytes.** Any run of 47 or more contains two identical, aligned blocks wherever the application's own prefix ends, so two equal ciphertext blocks identify ECB directly.
- **Search code and configuration** for `MODE_ECB`, `modes.ECB`, `aes-128-ecb`, `aes-256-ecb`, `AES/ECB`, and ECB options in database or storage settings. Also look for APIs that default to ECB, such as `Cipher.getInstance("AES")` in Java and MySQL's `AES_ENCRYPT()` with the default `block_encryption_mode`.

## Limitations

This demo is local and uses a known key. It does not model a remote exploit chain. The oracle has no rate limit, no prefix, and no authentication, so the query count would differ against a real service. I have not tested the solver against a network service or a production application, and I have not built the variable-length-prefix variant. These claims are limited to the local run, to the properties of ECB defined in the cited standards, and to the vendor documentation linked in this post.

## The complete script

Save it as `ecb_demo.py` and run `python3 ecb_demo.py`. The output is the two listings shown above: the three equality-demo blocks, then the attack results.

```python
"""Byte-at-a-time recovery of a secret from a local AES-128-ECB oracle.

Requires Python 3.9+ and the `cryptography` package.
"""
import string

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(16))
SECRET = b"demo{ecb_mode_leaks_structure}"
ALPHABET = (string.ascii_letters + string.digits + string.punctuation + " ").encode()
queries = 0


def ecb_encrypt(plaintext: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def oracle(prefix: bytes) -> bytes:
    global queries
    queries += 1
    padder = padding.PKCS7(128).padder()
    return ecb_encrypt(padder.update(prefix + SECRET) + padder.finalize())


def blocks(data: bytes, size: int) -> list[bytes]:
    return [data[i:i + size] for i in range(0, len(data), size)]


def show_equality() -> None:
    plaintext = b"A" * 32 + b"B" * 16
    ciphertext = ecb_encrypt(plaintext)
    for i, (p, c) in enumerate(zip(blocks(plaintext, 16), blocks(ciphertext, 16))):
        print(f"block {i}  {p.decode()}  ->  {c.hex()}")


def measure_parameters() -> tuple[int, int]:
    previous = len(oracle(b""))
    for n in range(1, 65):
        current = len(oracle(b"A" * n))
        if current > previous:
            block_size = current - previous
            secret_len = current - block_size - n
            return block_size, secret_len
        previous = current
    raise RuntimeError("no length change observed")


def recover_secret(block_size: int, secret_len: int) -> bytes:
    recovered = b""
    for i in range(secret_len):
        n = (block_size - 1 - i) % block_size
        index = (n + i) // block_size
        target = blocks(oracle(b"A" * n), block_size)[index]
        for candidate in ALPHABET:
            probe = oracle(b"A" * n + recovered + bytes([candidate]))
            if blocks(probe, block_size)[index] == target:
                recovered += bytes([candidate])
                break
        else:
            raise RuntimeError(f"no candidate matched at offset {i}")
    return recovered


def main() -> None:
    show_equality()
    print()
    block_size, secret_len = measure_parameters()
    print(f"block size: {block_size}")
    print(f"secret length: {secret_len} bytes")
    recovered = recover_secret(block_size, secret_len)
    print(f"recovered: {recovered!r}")
    print(f"queries: {queries}")


if __name__ == "__main__":
    main()
```

## References

- [FIPS 197: Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final), NIST.
- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final), NIST.
- [NIST SP 800-38D: Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final), NIST.
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439), IETF.
- [RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc5297), IETF.
- [Cryptopals Set 2, Challenge 12: Byte-at-a-time ECB decryption (Simple)](https://cryptopals.com/sets/2/challenges/12).
- [Symmetric encryption](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/), Python Cryptographic Authority.
- [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), OWASP.
- [MySQL Secure Deployment Guide: Block Encryption Mode Configuration](https://dev.mysql.com/doc/mysql-secure-deployment-guide/8.0/en/secure-deployment-block-encryption-mode.html), Oracle (MySQL 8.0).
- [JDK Providers Documentation](https://docs.oracle.com/pls/topic/lookup?ctx=javase12&id=security_guide_jdk_providers), Oracle (Java SE 12).
- [Using the Java Cryptographic Extensions](https://owasp.org/www-community/Using_the_Java_Cryptographic_Extensions), OWASP.
