# BLS Signatures Java

An implementation of BLS signatures on BLS12-381 (minimal-pubkey-size variant) compatible with Chia: [chia-bls](https://github.com/Chia-Network/chia_rs/tree/main/crates/chia-bls) (Rust) and [bls-signatures](https://github.com/Chia-Network/bls-signatures) (C++). It calls [blst](https://github.com/supranational/blst) **v0.3.17** directly through Java's Foreign Function & Memory API; there are no other runtime dependencies.

🚫 Security Disclaimer: This code has not undergone formal security audits. I started this as a hobbyist project primarily for learning and exploration. Please use at your own risk.

Feedback and PR's are very welcome.

## Requirements

- Java 22 or newer.
- Native access enabled for the library, otherwise the JVM prints a warning (and future JDKs will refuse):
  - classpath: `java --enable-native-access=ALL-UNNAMED ...`
  - module path: `java --enable-native-access=surf.superhighway.bls ...`
- A supported platform: Linux, macOS or Windows on x86_64 or aarch64 (Windows: x86_64). The jar built by CI bundles a native library for each. To use a library you built yourself, set `-Dsurf.superhighway.bls.library.path=/path/to/libchiabls.so`.

## Build

```shell
git clone --recurse-submodules https://github.com/navroudsari/java-bls-chia.git
cd java-bls-chia
mvn verify
```

`mvn` compiles blst plus [`native/chia_bls.c`](native/chia_bls.c) for the host with [`native/build.sh`](native/build.sh) (needs a C compiler; on Windows, MSYS2 MinGW). blst is built in portable mode, selecting CPU features at runtime, as chia-bls does. CI ([`.github/workflows/build.yml`](.github/workflows/build.yml)) builds and tests every platform and packages one jar containing all native libraries.

## Usage

```java
MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();

byte[] seed = new byte[32];
new SecureRandom().nextBytes(seed);

try (PrivateKey privateKey = PrivateKey.fromSeed(seed)) {    // destroyed (zeroized) on close
    Arrays.fill(seed, (byte) 0);

    PublicKey publicKey = privateKey.getPublicKey();
    byte[] message = {1, 2, 3, 4, 5};
    Signature signature = aug.sign(privateKey, message);

    boolean ok = aug.verify(publicKey, message, signature);
}
```

### Serialization

```java
byte[] publicKeyBytes = publicKey.toBytes();    // 48 bytes, compressed
byte[] signatureBytes = signature.toBytes();    // 96 bytes, compressed
byte[] privateKeyBytes = privateKey.toBytes();  // 32 bytes, big-endian; wipe when done

PublicKey pk = PublicKey.fromBytes(publicKeyBytes);   // checks encoding and G1 subgroup
Signature sig = Signature.fromBytes(signatureBytes);  // checks encoding and G2 subgroup
PrivateKey sk = PrivateKey.fromBytes(privateKeyBytes); // must be < group order
PrivateKey sk2 = PrivateKey.fromBytesModOrder(privateKeyBytes);
```

`fromBytesUnchecked` skips the subgroup check for trusted input; every verification method still rejects keys and signatures outside their subgroup.

### Aggregation

```java
Signature aggregate = aug.aggregateSignatures(List.of(signature1, signature2));
boolean ok = aug.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message1, message2), aggregate);

// Arbitrary trees of aggregates
Signature aggregateFinal = aug.aggregateSignatures(List.of(aggregate, signature3));
```

### Proof of possession

```java
ProofOfPossessionSignatureScheme pop = ProofOfPossessionSignatureScheme.getInstance();

// A proof of possession MUST be passed around with each public key and checked.
Signature proof = pop.popProve(privateKey);
boolean owned = pop.popVerify(publicKey, proof);

// Then many signatures on the same message verify quickly
boolean ok = pop.fastAggregateVerify(List.of(publicKey1, publicKey2, publicKey3), message, aggregate);
```

### HD keys

```java
// Hardened (EIP-2333 Lamport + KeyGen, as Chia does); no public derivation
PrivateKey child = master.deriveHardened(152);

// Unhardened (BIP32 style): public keys can be derived from public keys
PrivateKey childU = master.deriveUnhardened(22);
PublicKey childUPk = master.getPublicKey().deriveUnhardened(22);   // == childU.getPublicKey()

// Chia wallet paths (chia-bls derive_keys.rs)
PrivateKey wallet = HDKeys.masterToWalletUnhardened(master, 0);
PublicKey walletPk = HDKeys.masterToWalletUnhardened(master.getPublicKey(), 0);
```

Indices are unsigned 32-bit values passed as `int` (e.g. `0xFFFFFFFF`).

### chia-bls style functions

```java
Signature sig = Bls.sign(sk, message);                 // augmented: signs pk || message
boolean ok = Bls.verify(sig, pk, message);
boolean all = Bls.aggregateVerify(aggregate, List.of(pk1, pk2), List.of(msg1, msg2));

PublicKey g1 = Bls.hashToG1WithDst(message, dst);      // primitives used by CLVM operators
GTElement gt = Bls.hashToG2(augmented).pair(pk);

BlsCache cache = new BlsCache();                       // reuses pairings across verifications
boolean cached = cache.aggregateVerify(List.of(pk1, pk2), List.of(msg1, msg2), aggregate);
```

[`ReadmeExampleTest`](src/test/java/surf/superhighway/bls/ReadmeExampleTest.java) runs the full walkthrough.

## Memory handling of secret keys

Java cannot guarantee that secrets are erased, because the garbage collector copies heap objects. So private keys never live on the Java heap:

- Each key's scalar is stored in native memory, in slabs that are locked into RAM (`mlock` / `VirtualLock`) so they aren't swapped out, and on Linux excluded from core dumps. Locking is best effort and depends on OS limits (`ulimit -l`); `PrivateKey.isMemoryLocked()` reports whether it worked.
- Signing, derivation and aggregation run in native code directly on that memory. Hardened derivation's intermediate Lamport secrets (about 16 KB per step) are computed and scrubbed inside blst.
- `destroy()` / `close()` zeroizes the key immediately, and any later use throws `IllegalStateException`. Keys that are never destroyed are zeroized by a `Cleaner` once unreachable, at a time of the GC's choosing.
- `toString()` never shows key material, and `equals` compares in constant time.

Remaining exposure you control: the `byte[]` arguments and results of `fromSeed`, `fromBytes` and `toBytes` are ordinary heap arrays, so wipe them after use. Heap dumps, debuggers and anything else with access to process memory can still read live keys.

## Compatibility with chia-bls (Rust)

The API mirrors Chia's Rust crate [chia-bls](https://github.com/Chia-Network/chia_rs/tree/main/crates/chia-bls), the implementation the Chia node uses. Every chia-bls unit test is ported to Java and passes: [`RustPublicKeyTest`](src/test/java/surf/superhighway/bls/RustPublicKeyTest.java), [`RustSecretKeyTest`](src/test/java/surf/superhighway/bls/RustSecretKeyTest.java), [`RustSignatureTest`](src/test/java/surf/superhighway/bls/RustSignatureTest.java) and [`RustBlsCacheTest`](src/test/java/surf/superhighway/bls/RustBlsCacheTest.java). The only exceptions are its JSON tests, which exercise Python bindings. [`ChiaWalletKeysTest`](src/test/java/surf/superhighway/bls/ChiaWalletKeysTest.java) also reproduces real Chia wallet keys, from the master key down to the synthetic keys that sign spends.

| chia-bls | Java |
|---|---|
| `SecretKey` | `PrivateKey` (`from_seed` → `fromSeed`, `public_key` → `getPublicKey`, `+` → `add`) |
| `PublicKey` / `G1Element` | `PublicKey` |
| `Signature` / `G2Element` | `Signature` (`+=` / `aggregate` → `add`, returning a new value) |
| `GTElement` | `GTElement` (`*` → `multiply`) |
| `sign`, `sign_raw`, `verify`, `aggregate`, `aggregate_verify`, `aggregate_verify_gt`, `aggregate_pairing`, `hash_to_g1[_with_dst]`, `hash_to_g2[_with_dst]` | static methods on `Bls`, same argument order |
| `BlsCache` | `BlsCache` |
| `derive_unhardened` / `derive_hardened` | `deriveUnhardened` / `deriveHardened` |
| `master_to_wallet_*`, `master_to_pool_*` | `HDKeys.masterToWallet*`, `HDKeys.masterToPool*` |
| `Error` variants | `BlsException.getKind()`, same messages |
| `Debug` output (`<G1Element …>`, `<PrivateKey>`) | `toString()` |
| `negate`, `scalar_multiply`, `from_integer`, `from_uncompressed`, `pair`, `get_fingerprint` | same names in camelCase |

Value types are immutable in Java, so Rust's in-place operations (`negate()`, `+=`, `scalar_multiply`) return new objects instead.

Where this library deliberately differs from chia-bls:

- `BlsCache.aggregateVerify` rejects a public key outside G1 before computing or caching any pairing. chia-bls relies on keys having been validated when parsed. `Bls.aggregateVerify` behaves exactly like chia-bls, which already checks every key.
- `PublicKey.fromUncompressed` reports failures as `INVALID_PUBLIC_KEY`; chia-bls labels them `InvalidSignature`.
- Additions from Chia's C++ library (not in chia-bls): the basic and proof-of-possession schemes, and `Signature.deriveUnhardened`. They are tested against the C++ library's vectors and Chia's Python reference.
- Secret keys live off-heap and can be destroyed (see above). chia-bls keeps them in ordinary memory.

### Unsigned integers

Java has no unsigned primitives. This library follows one rule: a Rust fixed-width unsigned type becomes the Java type of the same width holding the same bits, and Java's unsigned helpers are used wherever the numeric value matters.

| Rust | Java | Notes |
|---|---|---|
| `u8` / `[u8; N]` | `byte` / `byte[]` | Bytes are opaque data. Equality and hashing work on the bit pattern, so sign never matters; mask with `& 0xff` only if you need the numeric value. |
| `u32` derivation index | `int` | Same 32 bits. `0xFFFFFFFF` (or `-1`) is index 4294967295; derivation serializes it big-endian, exactly as Rust's `to_be_bytes()`. Use `Integer.toUnsignedLong` / `Integer.parseUnsignedInt` to convert. |
| `u32` fingerprint | `long` | Returned already widened, so it prints and compares as the unsigned value Chia shows (e.g. 3020805514 for fingerprint `0xb40dd58a`, not a negative number). |
| Big integers / scalars | big-endian `byte[]` | `scalarMultiply` and `fromInteger` read unsigned big-endian bytes and reduce mod r, as chia-bls does. To bring a signed value (such as a CLVM atom, or Chia's synthetic-key offset) into that form, use `new BigInteger(bytes)` (signed), `.mod(r)`, then left-pad to 32 bytes. `new BigInteger(1, bytes)` is the unsigned reading. |

## Changes from 0.1

0.2 replaces jblst and Apache Tuweni and fixes several bugs, so the API has changed:

| 0.1 | 0.2 |
|---|---|
| `Bytes`, `Bytes32`, `Bytes48`, `UInt32` | `byte[]`, `int` |
| `XxxSignatureScheme.keygen(seed)` | `PrivateKey.fromSeed(seed)` |
| `serialize()` | `toBytes()` |
| `scheme.deriveChildPrivateKey(sk, i)` | `sk.deriveHardened(i)` |
| `scheme.deriveChildPrivateKeyUnhardened(sk, i)` | `sk.deriveUnhardened(i)` |
| `scheme.deriveChildPublicKeyUnhardened(pk, i)` | `pk.deriveUnhardened(i)` |
| `scheme.deriveChildSignatureUnhardened(sig, i)` | `sig.deriveUnhardened(i)` |
| `PublicKey.ZERO`, `Signature.ZERO` | `PublicKey.infinity()`, `Signature.infinity()` |
| `PrivateKey.ZERO` | `PrivateKey.fromBytes(new byte[32])` |
| `generate()` | `generator()` |
| `multiply(PublicKey)` | `scalarMultiply(byte[] bigEndianInteger)` |
| `getFingerprintAsHexString()` etc. | `getFingerprint()` (unsigned, as `long`) |
| `toString()` gave hex | `toString()` gives chia-bls's debug form, e.g. `<G1Element 97f1…>`; use `toBytes()` for the encoding |
| `IllegalStateException` / `IllegalArgumentException` for bad bytes | `BlsException` (an `IllegalArgumentException`) with chia-bls's error kinds |

Fixed in 0.2:
- `deriveChildPrivateKey` returned the parent key and overwrote the caller's parent with a child computed using the wrong KeyGen version.
- Unhardened derivation modified the caller's public key or signature, and could corrupt the shared `ZERO` constants.
- Unhardened signature derivation used the wrong byte order compared with Chia.
- `aggregateVerify` accepted public keys outside G1.
- `Signature.fromBytes` accepted points outside G2.
- `PrivateKey.fromBytes` accepted the group order itself.
- `PrivateKey.toString()` printed the secret key.
- `PublicKey.equals(null)` threw an exception.

## License

Apache 2.0. blst is used under the [Apache 2.0 license](https://github.com/supranational/blst/blob/master/LICENSE).
