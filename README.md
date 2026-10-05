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

In an existing clone, fetch blst first with `git submodule update --init`. Building needs JDK 22+.

`mvn` compiles blst plus [`native/chia_bls.c`](native/chia_bls.c) for the host with [`native/build.sh`](native/build.sh) (needs a C compiler; on Windows, MSYS2 MinGW). blst is built in portable mode, selecting CPU features at runtime, as chia-bls does. CI ([`.github/workflows/build.yml`](.github/workflows/build.yml)) builds and tests every platform and packages one jar containing all native libraries.

The library isn't published to Maven Central. To use it, either download the `java-bls-chia` artifact from a successful run of the build workflow (the jar for all platforms), or run `mvn install` to put a jar for your own platform in your local Maven repository.

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

Indices are `long` values from 0 to 4294967295 (Rust's `u32`); see [Integers](#integers-signed-unsigned-and-rusts-u32).

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

Remaining exposure you control: the `byte[]` arguments and results of `fromSeed`, `fromBytes`, `fromBytesModOrder` and `toBytes` are ordinary heap arrays, so wipe them after use. `asHexString()` returns a `String`, which can't be wiped at all; avoid it for real keys. Heap dumps, debuggers and anything else with access to process memory can still read live keys.

## Compatibility with chia-bls (Rust)

The API mirrors Chia's Rust crate [chia-bls](https://github.com/Chia-Network/chia_rs/tree/main/crates/chia-bls), the implementation the Chia node uses. Every chia-bls unit test (as of chia_rs commit [`6485640`](https://github.com/Chia-Network/chia_rs/commit/6485640), September 2026) is ported to Java and passes: [`RustPublicKeyTest`](src/test/java/surf/superhighway/bls/RustPublicKeyTest.java), [`RustSecretKeyTest`](src/test/java/surf/superhighway/bls/RustSecretKeyTest.java), [`RustSignatureTest`](src/test/java/surf/superhighway/bls/RustSignatureTest.java) and [`RustBlsCacheTest`](src/test/java/surf/superhighway/bls/RustBlsCacheTest.java). The only exceptions are its JSON tests, which exercise Python bindings. [`ChiaWalletKeysTest`](src/test/java/surf/superhighway/bls/ChiaWalletKeysTest.java) also reproduces real Chia wallet keys, from the master key down to the synthetic keys that sign spends.

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
- Additions from Chia's C++ library (not in chia-bls): the basic and proof-of-possession schemes, and `Signature.deriveUnhardened`. [`CppOracleTest`](src/test/java/surf/superhighway/bls/CppOracleTest.java) checks them against vectors generated by the C++ library itself ([`tools/oracle`](tools/oracle)): signatures, proofs of possession, aggregate and fast-aggregate verification (accepting and rejecting cases), and G2 derivation across the full index range.
- Secret keys live off-heap and can be destroyed (see above). chia-bls keeps them in ordinary memory.

### Integers: signed, unsigned and Rust's `u32`

Java has no unsigned primitives, so the API makes signedness explicit through types:

| Value | Rust | Java | Rule |
|---|---|---|---|
| Child index | `u32` | `long` | Must be in [0, 4294967295]; anything else throws `IllegalArgumentException`, so `-1` can't silently mean 4294967295. `int` arguments widen automatically. Serialized big-endian, like `u32::to_be_bytes`. |
| Fingerprint | `u32` | `long` | Holds the unsigned value Chia displays (3020805514, never negative). |
| Bytes / encodings | `u8`, `[u8; N]` | `byte` / `byte[]` | Opaque data; sign never matters. |
| Integer as `byte[]` | `&[u8]` | `byte[]` | **Always unsigned big-endian**, as in chia-bls: `scalarMultiply(byte[])`, `PublicKey.fromInteger(byte[])`, `PrivateKey.fromBytesModOrder`. |
| Integer of any sign | — | `BigInteger` | `scalarMultiply(BigInteger)`, `PublicKey.fromInteger(BigInteger)` and `Bls.modGroupOrder(BigInteger)` reduce mod r, wrapping negatives, exactly as CLVM's `g1_multiply`, `g2_multiply` and `pubkey_for_exp` do. |

To choose the signedness of raw bytes, pick the `BigInteger` constructor: `new BigInteger(bytes)` reads two's complement (CLVM atoms, Chia's synthetic-key offset), `new BigInteger(1, bytes)` reads unsigned. For example, Chia's synthetic key offset is:

```java
MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
sha256.update(publicKey.toBytes());
sha256.update(hiddenPuzzleHash);
byte[] digest = sha256.digest();
PrivateKey offset = PrivateKey.fromBytes(Bls.modGroupOrder(new BigInteger(digest)));   // signed!
```

[`IntegerTypesTest`](src/test/java/surf/superhighway/bls/IntegerTypesTest.java) runs 143 `g1_multiply`, `g2_multiply` and `pubkey_for_exp` cases from clvm_rs's operator tests, including negative scalars, through these overloads.

## Changes from 0.1

0.2 replaces jblst and Apache Tuweni and fixes several bugs, so the API has changed:

| 0.1 | 0.2 |
|---|---|
| `Bytes`, `Bytes32`, `Bytes48`, `UInt32` | `byte[]`; indices are `long` (range-checked u32) |
| `XxxSignatureScheme.keygen(seed)` | `PrivateKey.fromSeed(seed)` |
| `serialize()` | `toBytes()` |
| `scheme.deriveChildPrivateKey(sk, i)` | `sk.deriveHardened(i)` |
| `scheme.deriveChildPrivateKeyUnhardened(sk, i)` | `sk.deriveUnhardened(i)` |
| `scheme.deriveChildPublicKeyUnhardened(pk, i)` | `pk.deriveUnhardened(i)` |
| `scheme.deriveChildSignatureUnhardened(sig, i)` | `sig.deriveUnhardened(i)` |
| `PublicKey.ZERO`, `Signature.ZERO` | `PublicKey.infinity()`, `Signature.infinity()` |
| `PrivateKey.ZERO` | `PrivateKey.fromBytes(new byte[32])` |
| `generate()` | `generator()` |
| `PublicKey.multiply(PublicKey)`, `Signature.multiply(Signature)` | `scalarMultiply(byte[])` (unsigned big-endian) or `scalarMultiply(BigInteger)` (any sign) |
| `PublicKey.copy()`, `Signature.copy()` | Not needed: both are immutable, so share the instance (`PrivateKey.copy()` remains) |
| `PrivateKey.getSignature()` (sk × G2 generator) | `Signature.generator().scalarMultiply(sk.toBytes())`, wiping the array afterwards |
| `PrivateKey.signG2(msg, dst)` | `scheme.sign(sk, msg)` or `Bls.signRaw(sk, msg)`; signing under an arbitrary DST is no longer public, as in chia-bls |
| `HDKeys.keygen`, `HDKeys.deriveChildSk`, `HDKeys.parentSKToLamportPK` | `PrivateKey.fromSeed`, `sk.deriveHardened(i)`; the Lamport step is internal (native) |
| `HKDF`, `Util` | Removed (internal helpers) |
| `getFingerprintAsHexString()` etc. | `getFingerprint()` (unsigned, as `long`) |
| `toString()` gave hex | `toString()` gives chia-bls's debug form, e.g. `<G1Element 97f1…>`; use `toBytes()` for the encoding |
| `IllegalStateException` / `IllegalArgumentException` for bad bytes | `BlsException` (an `IllegalArgumentException`) with chia-bls's error kinds |
| `IllegalArgumentException` / `IllegalStateException` for null arguments | `NullPointerException` |
| `aggregateSignatures` / `aggregatePublicKeys` threw on an empty list | Return the identity (`infinity()`), as Chia does |
| Java 17 | Java 22+, with native access enabled (see Requirements) |

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
