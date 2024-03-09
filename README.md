# fernet-ts

Fernet algorithm implementation written in Typescript (Compatible with browsers, Deno 1.11+, Node.js 19+ and maybe other runtimes).

This implementation is interoperable with Python version of Fernet.
Encrypted text in this Typescript implementation can be decrypted using Python Fernet library and vice versa.

## Installation

Use the package manager [npm](https://github.com/npm/cli) to install [fernet-ts](https://www.npmjs.com/package/fernet-ts).

```bash
npm i fernet-ts
```

## Usage

```typescript
import { Fernet } from 'fernet-ts';

// Generate secret key
// Returns 32-byte long base64url encoded string
// Example: "Brxd-7fAiRQFYz2eI81ZNzCzJwf7BjAsMjtx-_KH5wo="
const secret = Fernet.generateSecret();

// some random text to encrypt
const message = "This is a top secret message!";

// create new Fernet instance
const f = await Fernet.getInstance(secret);

// encrypt message
// returns base64url encoded string
// Example: "gAAAAABkASMLGab74DqnryApsIrMxLsb5lvRUMnc6YzNYMEt79UVUOBQyqhqGiQu7G9s9h9wnDyWBa78odzUCJvx9jJi5ENrqAL_T6xEgRTmn43mtXOQ42Y="
const token = await f.encrypt(message);

// decrypt token and get message
// returns origin plain text message
// Example: "This is a top secret message!"
const plainText = await f.decrypt(token);

// You can also use static methods for encryption/decryption
const fernetToken = await Fernet.encrypt(message, secret);
const decryptedText = await Fernet.decrypt(fernetToken, secret);

```

## Fernet Spec

This document describes version 0x80 (currently the only
version) of the fernet format.

Conceptually, fernet takes a user-provided *message* (an arbitrary
sequence of bytes), a *key* (256 bits === 32 bytes), and the current
time, and produces a *token*, which contains the message in a form
that can't be read or altered without the key.

To facilitate convenient interoperability, this spec defines the
external format of both tokens and keys.

All encryption in this version is done with AES 128 in CBC mode.

All base 64 encoding is done with the "URL and Filename Safe"
variant, defined in [RFC 4648](http://tools.ietf.org/html/rfc4648#section-5) as "base64url".

## Key Format

A fernet *key* is the base64url encoding of the following
fields:

```text
    Signing-key ‖ Encryption-key
```

- *Signing-key*, 128 bits
- *Encryption-key*, 128 bits

## Token Format

A fernet *token* is the base64url encoding of the
concatenation of the following fields:

```text
    Version ‖ Timestamp ‖ IV ‖ Ciphertext ‖ HMAC
```

- *Version*, 8 bits (1 byte)
- *Timestamp*, 64 bits (8 bytes)
- *IV*, 128 bits (16 bytes)
- *Ciphertext*, variable length, multiple of 128 bits (16 bytes)
- *HMAC*, 256 bits (32 bytes)

Fernet tokens are not self-delimiting. It is assumed that the
transport will provide a means of finding the length of each
complete fernet token.

## Token Fields

### Version

This field denotes which version of the format is being used by
the token. Currently there is only one version defined, with the
value 128 (0x80).

### Timestamp

This field is a 64-bit unsigned big-endian integer. It records the
number of seconds elapsed between January 1, 1970 UTC and the time
the token was created.

### IV

The 128-bit Initialization Vector used in AES encryption and
decryption of the Ciphertext.

When generating new fernet tokens, the IV must be chosen uniquely
for every token. With a high-quality source of entropy, random
selection will do this with high probability.

### Ciphertext

This field has variable size, but is always a multiple of 128
bits, the AES block size. It contains the original input message,
padded and encrypted.

### HMAC

This field is the 256-bit SHA256 HMAC, under signing-key, of the
concatenation of the following fields:

```text
    Version ‖ Timestamp ‖ IV ‖ Ciphertext
```

Note that the HMAC input is the entire rest of the token verbatim,
and that this input is *not* base64url encoded.

## Generating

Given a key and message, generate a fernet token with the
following steps, in order:

1. Record the current time for the timestamp field.
2. Choose a unique IV.
3. Construct the ciphertext:
   1. Pad the message to a multiple of 16 bytes (128 bits) per [RFC
   5652, section 6.3](http://tools.ietf.org/html/rfc5652#section-6.3).
   This is the same padding technique used in [PKCS #7
   v1.5](http://tools.ietf.org/html/rfc2315#section-10.3) and all
   versions of SSL/TLS (cf. [RFC 5246, section
   6.2.3.2](http://tools.ietf.org/html/rfc5246#section-6.2.3.2) for
   TLS 1.2).
   2. Encrypt the padded message using AES 128 in CBC mode with
   the chosen IV and user-supplied encryption-key.
4. Compute the HMAC field as described above using the
user-supplied signing-key.
5. Concatenate all fields together in the format above.
6. base64url encode the entire token.

## Verifying

Given a key and token, to verify that the token is valid and
recover the original message, perform the following steps, in
order:

1. base64url decode the token.
2. Ensure the first byte of the token is 0x80.
3. If the user has specified a maximum age (or "time-to-live") for
the token, ensure the recorded timestamp is not too far in the
past.
4. Recompute the HMAC from the other fields and the user-supplied
signing-key.
5. Ensure the recomputed HMAC matches the HMAC field stored in the
token, using a constant-time comparison function.
6. Decrypt the ciphertext field using AES 128 in CBC mode with the
recorded IV and user-supplied encryption-key.
7. Unpad the decrypted plaintext, yielding the original message.
