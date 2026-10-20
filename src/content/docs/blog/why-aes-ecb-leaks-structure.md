---
title: "Why AES-ECB Leaks Structure: A Byte-at-a-Time Oracle"
description: "A local AES-ECB oracle that recovers a 30-byte secret one byte at a time, why deterministic block encryption leaks equality, and what to use instead."
type: blog
blog_type: analysis
tags:
  - cryptography
  - aes
  - ecb
  - python
---

AES-ECB encrypts each 16-byte block independently. Equal plaintext blocks become equal ciphertext blocks under the same key. An attacker who can submit chosen input and read the ciphertext can use that equality to recover a secret without attacking AES itself.

I built a local oracle around AES-128-ECB and recovered a 30-byte secret in 853 queries. The solver never sees the key. It compares ciphertext blocks and keeps the candidate that produces a match.

## The property that breaks it

ECB is a mode of operation; AES is the cipher. FIPS 197 defines AES, and NIST SP 800-38A defines ECB and the other modes. Under ECB, each block is encrypted on its own:

```text
C[i] = E(K, P[i])
```

There is no chaining value, no initialization vector, and no per-message state. Two identical plaintext blocks therefore produce identical ciphertext blocks:

```text
block 0  AAAAAAAAAAAAAAAA  ->  dd4b1a0b47daa7067d0b59d95d58a6ae
block 1  AAAAAAAAAAAAAAAA  ->  dd4b1a0b47daa7067d0b59d95d58a6ae
block 2  BBBBBBBBBBBBBBBB  ->  87f815ad0e513346e0afe99814b1a504
```

Those values come from AES-128 with the key `000102...0f`. A viewer who sees the first two blocks can tell that the first two plaintext blocks were identical, even without the key. The exact bytes do not matter.

This is the same property behind the ECB penguin: large runs of one colour in an image survive encryption as repeated ciphertext blocks, so the outline remains visible. ECB hides the contents of each block, while the pattern between blocks remains visible.

## A local oracle

The demo needs Python 3 and the `cryptography` package. It uses a fixed key and a fixed secret. It places attacker input before a fixed blob, so the input shifts the secret across block boundaries.

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import string

KEY = bytes(range(16))
SECRET = b"demo{ecb_mode_leaks_structure}"
FIXED = b"|" + SECRET
ALPHABET = (string.ascii_letters + string.digits + string.punctuation + " ").encode()
queries = 0


def oracle(prefix: bytes) -> bytes:
    global queries
    queries += 1
    pt = prefix + FIXED
    padder = padding.PKCS7(128).padder()
    pt = padder.update(pt) + padder.finalize()
    enc = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
    return enc.update(pt) + enc.finalize()


def blocks(data: bytes, block_size: int) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]
```

`FIXED` is 31 bytes, so it is not block aligned. PKCS#7 padding brings an empty input to 32 bytes, which is two blocks. The delimiter is part of the fixed blob on purpose: the solver recovers it as the first byte and strips it afterwards.

I fixed the key so the run is reproducible. A real target keeps its key secret, and the attack never needs it.

## Measure the block size and fixed length

Ciphertext length grows in block-sized steps. The first increase gives both the block size and the length of the fixed data.

```python
def measure_parameters() -> tuple[int, int]:
    previous = len(oracle(b""))
    for n in range(1, 65):
        current = len(oracle(b"A" * n))
        if current > previous:
            block_size = current - previous
            fixed_len = (current // block_size - 1) * block_size - n
            return block_size, fixed_len
        previous = current
    raise RuntimeError("no length change observed")


block_size, fixed_len = measure_parameters()
print(f"block size: {block_size}")
print(f"fixed length: {fixed_len} bytes")
```

With a 31-byte fixed blob, the first jump happens at `n = 1`. The input plus fixed data reaches 32 bytes, padding adds a full block, and the ciphertext goes from 32 to 48 bytes. The formula subtracts the padding block and the one byte of filler:

```text
(48 // 16 - 1) * 16 - 1 = 31
```

Output:

```text
block size: 16
fixed length: 31 bytes
```

Those 31 bytes are the delimiter plus 30 secret bytes. With block-aligned fixed data, the first jump would happen later, and the same formula still applies.

## Recover one byte at a time

At offset `i`, choose filler length `n = (16 - 1 - i) % 16`. That places the unknown byte at the last position of block `(n + i) // 16`.

For the first byte, `i = 0` and `n = 15`. The target query encrypts 15 `A` bytes followed by the fixed blob. Block 0 holds `AAAAAAAAAAAAAAA` plus the first fixed byte. For the second byte, `i = 1` and `n = 14`. Block 0 holds 14 `A` bytes, the first recovered byte, and the next unknown byte.

The target block comes from a query whose input is only filler, so the unknown byte sits at the block edge. Each candidate comes from a query with the filler, the bytes recovered so far, and the candidate byte. When the candidate is correct, the two 16-byte blocks are identical.

```python
recovered = b""

for i in range(fixed_len):
    n = (block_size - 1 - i) % block_size
    block_index = (n + i) // block_size
    target = blocks(oracle(b"A" * n), block_size)[block_index]

    for candidate in ALPHABET:
        probe = blocks(oracle(b"A" * n + recovered + bytes([candidate])), block_size)[block_index]
        if probe == target:
            recovered += bytes([candidate])
            break
    else:
        raise RuntimeError(f"no candidate matched at offset {i}")
```

The alignment for the first two blocks looks like this:

| Offset `i` | Filler `n` | Block | Unknown byte position |
|---:|---:|---:|---:|
| 0 | 15 | 0 | 15 |
| 1 | 14 | 0 | 15 |
| 15 | 0 | 0 | 15 |
| 16 | 15 | 1 | 31 |

The comparison is an equality test. The solver never decrypts anything. Only the oracle touches the key, and the solver only asks whether two ciphertext blocks match.

## The run

```text
block size: 16
fixed length: 31 bytes
recovered: b'|demo{ecb_mode_leaks_structure}'
queries: 853
```

This blob starts with the delimiter. `recovered[1:]` is the demo secret.

I used 95 printable ASCII candidates, so 31 bytes cost 853 queries, about 27 per byte. Keeping the alphabet to printable ASCII made the recovered string easy to inspect. A binary secret needs all 256 byte values. I did not run that variant, but the loop is the same. The alphabet size and the position of the correct byte set the cost.

## What the attack needs

An oracle must be deterministic and the fixed data must stay in the same position across queries. When an application adds a random prefix on every request, the block boundaries move and the target block changes. The simple comparison fails, and the attacker has to find a stable alignment first.

An attacker also needs chosen plaintext and the resulting ciphertext. A single captured ciphertext is not enough. When an application compresses or encodes the secret before encryption, the attack recovers the encoded form.

This does not recover the AES key, and it does not apply to a correctly used AEAD. It recovers plaintext from a mode that leaks block equality.

## What else the leak enables

The same equality leak enables block reordering, cut-and-paste, and pattern recognition. The byte-at-a-time oracle turns the leak into full plaintext recovery with a small amount of code.

ECB still appears in legacy storage, database encryption settings, and embedded code because it is simple and parallel. Those properties explain why the mode survives. They do not make it safe for structured or multi-block data.

The failure is in the mode choice. AES-128 with ECB is still AES. The mode drops the chaining that hides block equality. A longer key does not restore it.

## What to use instead

For new designs, use an AEAD such as AES-GCM or ChaCha20-Poly1305. Both provide confidentiality and integrity, and both require a unique nonce per message under a given key.

If the design needs deterministic ciphertexts, use a dedicated deterministic AEAD such as AES-SIV (RFC 5297) and document the equality leak. Do not invent a mode or add a fixed IV to CBC and call it deterministic.

For existing code, search for ECB identifiers and replace the construction. Rotating the key does not fix a mode that leaks block equality.

Checks that catch the mistake:

- Encrypt the same plaintext twice. Identical ciphertexts mean deterministic encryption. That may be intentional, but it needs a documented reason.
- Encrypt a long run of repeated bytes. Repeated ciphertext blocks identify ECB directly.
- Search for `MODE_ECB`, `modes.ECB`, `aes-128-ecb`, `aes-256-ecb`, and ECB options in database or storage configuration.
- Add a test that two encryptions of the same plaintext differ, where the design expects randomized encryption. This catches accidental ECB in application code, not in legacy storage that intentionally uses deterministic encryption.

## Limitations

This demo is local and uses a known key. It does not model a remote exploit chain. This oracle has no rate limit, no random prefix, and no authentication, so the query count would change against a real service.

I have not tested the solver against a network service or a production application. These claims are limited to the local run and to the properties of ECB defined in the cited standards.

## References

- [FIPS 197: Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final), NIST.
- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final), NIST.
- [NIST SP 800-38D: Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final), NIST.
- [RFC 5297: Synthetic Initialization Vector (SIV) Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc5297), IETF.
- [Symmetric encryption](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/), Python Cryptographic Authority.
- [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), OWASP.
