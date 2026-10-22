---
title: "AES-CBC Padding Oracles: Decrypting Secrets and Encrypting Commands"
description: "A local AES-128-CBC oracle that leaks only padding validity is enough to recover plaintext byte by byte and to build ciphertext for an arbitrary command."
type: blog
blog_type: analysis
tags:
  - cryptography
  - aes
  - cbc
  - padding-oracle
  - python
---

AES-CBC chains each plaintext block to the previous ciphertext block. That chaining lets an attacker flip a plaintext bit by changing the preceding ciphertext block. If a service also reports whether the decrypted padding is valid, the attacker can turn that one bit into a decryption oracle and recover the plaintext without the key.

The same oracle also works in reverse. Once it has recovered `D_K(C)` for a ciphertext block, the attacker can choose the preceding block so the target decrypts to any plaintext. Repeating that step builds a complete ciphertext for a chosen message. The technique is called CBC-R, and it turns a padding oracle into an encryption oracle.

Both directions are practical when a service leaks padding validity and accepts attacker-chosen ciphertext. The demo below uses a local AES-128-CBC oracle. It recovers a 30-byte secret in 3,859 queries and encrypts a 21-byte command in 4,393 queries.

## CBC and PKCS#7 padding

With plaintext blocks `P_1` to `P_n`, ciphertext blocks `C_1` to `C_n`, and an initialization vector `C_0`, CBC encryption and decryption are:

```text
C_i = E_K(P_i XOR C_{i-1})
P_i = D_K(C_i) XOR C_{i-1}
```

The IV is not secret and is not a key. It randomizes the first block. CBC provides confidentiality only, and it does not authenticate the message.

PKCS#7 pads the last block to 16 bytes. If the final block is short by `n` bytes, append `n` bytes with value `n`. If the plaintext is already aligned, append a full block of `0x10`. On decryption, the receiver reads the last byte, checks that it is between 1 and 16, and checks that the same number of trailing bytes carry that value. A failed check is a padding error.

The padding result is the only signal the attacker needs. The attacker does not need the plaintext or the key, only a valid or invalid answer. Serge Vaudenay described the decryption attack in 2002, and it applies whenever a service checks CBC padding before checking integrity.

## A one-bit oracle

The demo exposes one operation: send `IV || ciphertext`, receive a boolean. The function decrypts under a fixed AES-128 key and checks the padding. It never returns plaintext, and it does not say which byte failed.

```python
BLOCK = 16


def valid_padding(data: bytes) -> bool:
    n = data[-1]
    return 1 <= n <= BLOCK and data[-n:] == bytes([n]) * n


def oracle(data: bytes) -> bool:
    global queries
    queries += 1
    if len(data) < 2 * BLOCK or len(data) % BLOCK:
        return False
    return valid_padding(cbc_decrypt(data[BLOCK:], data[:BLOCK]))
```

Real services leak the same bit in different ways: a 200 versus 500 response, an error string, a different connection close, or a timing difference. The attack only needs a reliable distinction; the cause of the difference does not matter.

## Recovering one block

Fix a target block `C_i`. Send `C' || C_i`. The first block is the IV for this two-block message. The plaintext of the target block is:

```text
P = D_K(C_i) XOR C'
```

Every byte of `C'` is chosen by the attacker, so every byte of `P` can be shifted independently. To make the last plaintext byte `0x01`, set the last byte of `C'` to `g XOR 0x01` and try every value of `g`. A valid padding response normally means `g` is the last byte of `D_K(C_i)`; the exception is the false positive covered below.

For the next byte, keep the last plaintext byte at `0x02`, then vary the second-to-last byte. The target plaintext ends in `0x02 0x02` when the guess is correct. Continue until all 16 bytes are known. In the table, `D` is `D_K(C_i)`.

| Padding | Bytes set in `C'` | Target plaintext tail |
|---|---|---|
| `0x01` | `C'[15] = g XOR 0x01` | `... 01` |
| `0x02` | `C'[15] = D[15] XOR 0x02`, `C'[14] = g XOR 0x02` | `... 02 02` |
| `0x03` | `C'[15] = D[15] XOR 0x03`, `C'[14] = D[14] XOR 0x03`, `C'[13] = g XOR 0x03` | `... 03 03 03` |

The first query is ambiguous. A valid response for padding 1 can come from a last plaintext byte of `0x01`, but it can also come from `0x02 0x02` or a longer run. The script performs a second query with one bit flipped in the preceding ciphertext byte, which flips the corresponding plaintext bit. If the last byte is `0x01`, that plaintext byte sits outside the padding and the response remains valid. If the padding is longer, the flip breaks it and the response becomes invalid. This check runs only for the last byte. For later bytes, the last byte is fixed to the target padding value, so a valid response cannot come from a different padding length.

The full recovery follows the [Cryptopals Set 3, Challenge 17](https://cryptopals.com/sets/3/challenges/17) exercise.

```python
def recover_intermediate(target: bytes) -> bytes:
    """Recover D_K(target) by manipulating the preceding block."""
    intermediate = bytearray(BLOCK)
    for padding in range(1, BLOCK + 1):
        pos = BLOCK - padding
        crafted = bytearray(BLOCK)
        for j in range(pos + 1, BLOCK):
            crafted[j] = intermediate[j] ^ padding
        for guess in range(256):
            crafted[pos] = guess ^ padding
            if not oracle(bytes(crafted) + target):
                continue
            if padding == 1:
                check = bytearray(crafted)
                check[pos - 1] ^= 1
                if not oracle(bytes(check) + target):
                    continue
            intermediate[pos] = guess
            break
        else:
            raise RuntimeError(f"no byte found at position {pos}")
    return bytes(intermediate)
```

The loop makes up to 4,096 guesses per block (16 bytes times 256 candidates), plus the extra queries for the last-byte check. Early guesses reduce the count, so the exact figure depends on the recovered bytes and the order in which guesses are tried.

## Decrypting a message

To decrypt a full message, recover `D_K(C_i)` for each block, then XOR it with the real previous block. For the first block, the previous value is the IV.

```python
def decrypt_ciphertext(data: bytes) -> tuple[bytes, bytes]:
    iv, ciphertext = data[:BLOCK], data[BLOCK:]
    chunks = blocks(ciphertext)
    plaintext = [b""] * len(chunks)
    for i in range(len(chunks) - 1, -1, -1):
        d = recover_intermediate(chunks[i])
        previous = chunks[i - 1] if i else iv
        plaintext[i] = xor(d, previous)
    padded = b"".join(plaintext)
    return unpad(padded), padded
```

The target block is always the last block of the two-block query. The crafted IV only satisfies the oracle and is discarded. The loop can run in any order; the demo goes backwards.

The demo encrypts a 30-byte secret under a fixed key and IV, then attacks the result:

```text
padded plaintext: b'demo{padding_oracle_recovered}\x02\x02'
recovered secret: b'demo{padding_oracle_recovered}'
decryption queries: 3859
```

The recovered intermediate values show the XOR step. For the second block:

```text
D(C_2) = 9d12b0063473ca6dcab1d83d7a7e9476
C_1    = fe7ed5594616a902bcd4aa581e039674
P_2    = 636c655f7265636f76657265647d0202
```

`P_2` is `b'cle_recovered}\x02\x02'`. The padding bytes are visible because the attack recovers the plaintext exactly as CBC decrypts it, including the padding.

## Building ciphertext backwards

CBC-R uses the same primitive. Rizzo and Duong described the construction in their 2010 paper on practical padding oracle attacks. Choose a final ciphertext block `C_n`, recover `D_K(C_n)`, and use it to choose the block before it. To make the last plaintext block `P_n`, set:

```text
C_{n-1} = P_n XOR D_K(C_n)
```

Then recover `D_K(C_{n-1})` and set `C_{n-2} = P_{n-1} XOR D_K(C_{n-1})`. Continue to `C_0`, which becomes the IV:

```text
choose C_n
for i = n down to 1:
    D_i = recover_intermediate(C_i)
    C_{i-1} = P_i XOR D_i
return C_0 || C_1 || ... || C_n
```

Each step recovers the decryption of the block just computed. The oracle treats the chosen block like any other ciphertext block.

```python
def encrypt_plaintext(plaintext: bytes) -> bytes:
    chunks = blocks(pad(plaintext))
    chain = [LAST_BLOCK]
    for chunk in reversed(chunks):
        d = recover_intermediate(chain[0])
        chain.insert(0, xor(chunk, d))
    return chain[0] + b"".join(chain[1:])
```

`LAST_BLOCK` is fixed in the demo so the run is reproducible. Any 16-byte value works because the next step uses `D_K(C_n)` only to choose `C_{n-1}`. A real attack would use a random block.

## Encrypting a command

The command is ordinary plaintext. Pad it with PKCS#7, split it into 16-byte blocks, and run the loop. The demo uses `cat /etc/hostname; id`.

```python
COMMAND = b"cat /etc/hostname; id"

queries = 0
command_ct = encrypt_plaintext(COMMAND)
print(f"encryption queries: {queries}")
print(f"worker output: {worker(command_ct)!r}")
```

The worker decrypts, checks the padding, and returns the command text. It does not execute anything. The full script also flips the final ciphertext byte and sends the result to the worker.

```text
encryption queries: 4393
worker output: b'cat /etc/hostname; id'
corrupted ciphertext: b'Error: invalid padding'
```

The same function works for any byte string. A command is one example: if the application passes the plaintext to a shell, the bytes become a command; if it parses them as JSON, they become JSON. CBC-R controls the bytes, not how the application interprets them.

Changing a byte in the final ciphertext block changes the last plaintext block and usually breaks the padding. The demo flips the final byte and the worker rejects it. CBC has no integrity check, so an application that acts on decrypted data must add one.

## What the attack requires

The decryption direction needs a padding oracle that accepts chosen ciphertext and reveals whether the final padding is valid. It also needs control of the block before the target block, because changing that block changes the target plaintext.

The encryption direction needs the same oracle, the ability to choose the final ciphertext block, and control of the IV or a preceding ciphertext block. If the service only accepts a fixed token, or if it authenticates the ciphertext before checking padding, the attack does not apply.

Rate limiting raises the cost but does not remove the oracle. A WAF rule that blocks repeated bad padding may slow the attack, but the construction remains vulnerable.

## Fixing it

Use an AEAD. AES-GCM and ChaCha20-Poly1305 encrypt and authenticate in one construction. Each message needs a unique nonce. The receiver rejects a forged ciphertext before using the plaintext.

If CBC is required by an existing protocol, use encrypt-then-MAC: compute an HMAC with an independent key over the IV and ciphertext, verify it in constant time, and only then decrypt. Return one generic error for every failure. Do not reveal whether padding, MAC, or parsing failed.

Constant-time unpadding helps against timing leaks, but it is not a substitute for authentication. If the service exposes the result of the padding check, the oracle remains.

To test a service, flip bytes in a ciphertext and compare status codes, response bodies, and timing. If valid and invalid padding produce different observable behavior, the service has an oracle. Then check whether the MAC is verified first.

## Limitations

The demo is local and uses a known key because it simulates the service. The attack code never uses `KEY` directly; it calls the oracle, which does. There is no network transport, no rate limit, no constant prefix before the plaintext, and no authentication. The query counts are from this run and would differ against a real service.

The attack recovers plaintext, not the AES key. It does not apply to a correctly used AEAD. CBC-R needs a padding oracle that accepts chosen ciphertext, the ability to choose the final block, and control of the IV or a preceding ciphertext block. The worker in the demo does not execute the command; it only returns the decrypted bytes.

## The complete script

Save it as `cbc_demo.py` and run it with Python 3.9 or later. It needs the `cryptography` package. The script also prints the generated ciphertexts; the excerpts above omit those lines for brevity.

```python
"""Local AES-128-CBC padding-oracle demo: decrypt and encrypt."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16
KEY = bytes(range(16))
IV = bytes(range(16, 32))
SECRET = b"demo{padding_oracle_recovered}"
COMMAND = b"cat /etc/hostname; id"
LAST_BLOCK = bytes(range(32, 48))
queries = 0


def cbc_encrypt(plaintext: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def cbc_decrypt(ciphertext: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def pad(data: bytes) -> bytes:
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    n = data[-1]
    if not 1 <= n <= BLOCK or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid padding")
    return data[:-n]


def valid_padding(data: bytes) -> bool:
    n = data[-1]
    return 1 <= n <= BLOCK and data[-n:] == bytes([n]) * n


def oracle(data: bytes) -> bool:
    """Return True if data decrypts to a validly padded plaintext.

    data is IV || ciphertext. The caller controls both parts.
    """
    global queries
    queries += 1
    if len(data) < 2 * BLOCK or len(data) % BLOCK:
        return False
    return valid_padding(cbc_decrypt(data[BLOCK:], data[:BLOCK]))


def blocks(data: bytes) -> list[bytes]:
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def recover_intermediate(target: bytes) -> bytes:
    """Recover D_K(target) by manipulating the preceding block."""
    intermediate = bytearray(BLOCK)
    for padding in range(1, BLOCK + 1):
        pos = BLOCK - padding
        crafted = bytearray(BLOCK)
        for j in range(pos + 1, BLOCK):
            crafted[j] = intermediate[j] ^ padding
        for guess in range(256):
            crafted[pos] = guess ^ padding
            if not oracle(bytes(crafted) + target):
                continue
            if padding == 1:
                check = bytearray(crafted)
                check[pos - 1] ^= 1
                if not oracle(bytes(check) + target):
                    continue
            intermediate[pos] = guess
            break
        else:
            raise RuntimeError(f"no byte found at position {pos}")
    return bytes(intermediate)


def decrypt_ciphertext(data: bytes) -> tuple[bytes, bytes]:
    iv, ciphertext = data[:BLOCK], data[BLOCK:]
    chunks = blocks(ciphertext)
    plaintext = [b""] * len(chunks)
    for i in range(len(chunks) - 1, -1, -1):
        d = recover_intermediate(chunks[i])
        previous = chunks[i - 1] if i else iv
        plaintext[i] = xor(d, previous)
    padded = b"".join(plaintext)
    return unpad(padded), padded


def encrypt_plaintext(plaintext: bytes) -> bytes:
    chunks = blocks(pad(plaintext))
    chain = [LAST_BLOCK]
    for chunk in reversed(chunks):
        d = recover_intermediate(chain[0])
        chain.insert(0, xor(chunk, d))
    return chain[0] + b"".join(chain[1:])


def worker(data: bytes) -> bytes:
    """Mock worker: decrypt, validate padding, return the command."""
    raw = cbc_decrypt(data[BLOCK:], data[:BLOCK])
    if not valid_padding(raw):
        return b"Error: invalid padding"
    return unpad(raw)


def main() -> None:
    global queries

    secret_ct = IV + cbc_encrypt(pad(SECRET), IV)
    print(f"secret ciphertext: {secret_ct.hex()}")

    queries = 0
    recovered, padded = decrypt_ciphertext(secret_ct)
    print(f"padded plaintext: {padded!r}")
    print(f"recovered secret: {recovered!r}")
    print(f"decryption queries: {queries}")

    queries = 0
    command_ct = encrypt_plaintext(COMMAND)
    print(f"command ciphertext: {command_ct.hex()}")
    print(f"encryption queries: {queries}")

    print(f"worker output: {worker(command_ct)!r}")

    broken = bytearray(command_ct)
    broken[-1] ^= 1
    print(f"corrupted ciphertext: {worker(bytes(broken))!r}")


if __name__ == "__main__":
    main()
```

## References

- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final), NIST.
- [RFC 5652: Cryptographic Message Syntax](https://www.rfc-editor.org/rfc/rfc5652), IETF. Section 6.3 defines this padding method.
- [Security Flaws Induced by CBC Padding](https://link.springer.com/chapter/10.1007/3-540-46035-7_35), Serge Vaudenay, EUROCRYPT 2002.
- [Practical Padding Oracle Attacks](https://www.usenix.org/legacy/events/woot10/tech/full_papers/Rizzo.pdf), Juliano Rizzo and Thai Duong, WOOT 2010. Section 4.1.1 describes CBC-R.
- [Cryptopals Set 3, Challenge 17: The CBC Padding Oracle](https://cryptopals.com/sets/3/challenges/17).
- [NIST SP 800-38D: Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final), NIST.
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439), IETF.
- [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), OWASP.
