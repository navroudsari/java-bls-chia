# BLS Signatures Java

An implementation of BLS signatures using [blst](https://github.com/supranational/blst) Java bindings based on [Chia's implementation](https://github.com/Chia-Network/bls-signatures). This library implements the Minimal Pubkey Size variant.

🚫 Security Disclaimer: This code has not undergone formal security audits. I started this as a hobbyist project primarily for learning and exploration. Please use at your own risk.

It's currently using [Consensys' jblst](https://github.com/Consensys/jblst), a packaged cross-platform version of blst for java.  You may prefer to build the [blst jar](https://github.com/supranational/blst/tree/master/bindings/java) from source yourself if you don't trust their package.

Feedback and PR's are very welcome.

# Usage

## Get instance of scheme

```java
SignatureScheme basicScheme = BasicSignatureScheme.getInstance();
SignatureScheme augScheme = MessageAugmentationSignatureScheme.getInstance();
ProofOfPossessionSignatureScheme popScheme = ProofOfPossessionSignatureScheme.getInstance();
```

## Sign message using message augmentation signature scheme

```java
// Fetch signature scheme instance
SignatureScheme augScheme = MessageAugmentationSignatureScheme.getInstance();

// Generate a keypair
PrivateKey privateKey = MessageAugmentationSignatureScheme.keygen(secureRandom.generateSeed(32));
PublicKey publicKey = augScheme.privateKeyToPublicKey(privateKey);

// A message to sign
Bytes messageBytes = Bytes.secure("Hello, World!".getBytes());

// Sign message with private key
Signature signature = augScheme.sign(privateKey, messageBytes);

// Verify message with public key and signature
boolean verified = augScheme.verify(publicKey, messageBytes, signature);
```

## Verify ownership of public key using Proof of Possession (POP) Signature Scheme
```java
// Fetch POP signature scheme instance
ProofOfPossessionSignatureScheme popScheme = ProofOfPossessionSignatureScheme.getInstance();

// Party A generates keypair and shares their public key
PrivateKey partyAPrivateKey = ProofOfPossessionSignatureScheme.keygen(secureRandom.generateSeed(32));
PublicKey partyAPublicKey = popScheme.privateKeyToPublicKey(privateKey);

// Party A creates a signature to prove they own the shared public key
Signature partyAProofOfPossessionSignature = popScheme.popProve(privateKey);

// Party B verifies that Party A does indeed own the shared public key using the created signature
boolean doTheyOwnThePublicKey = popScheme.popVerify(partyAPublicKey, partyAProofOfPossessionSignature);
```

# Run Tests

```shell
mvn test
```

```shell
[INFO] Results:
[INFO] 
[INFO] Tests run: 36, Failures: 0, Errors: 0, Skipped: 0
[INFO] 
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  1.264 s
```

# Examples Adapted From Chia's BLS Signatures Repo
## Creating keys and signatures example

```java
// Example seed, used to generate private key. Always use a secure RNG
// with sufficient entropy to generate a seed (at least 32 bytes).
Bytes seed = Bytes.of(
    0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192, 19, 
    18, 12, 89, 6, 220, 18, 102, 58, 209, 82, 12, 
    62, 89, 110, 182, 9, 44, 20, 254, 22);

PrivateKey privateKey = MessageAugmentationSignatureScheme.keygen(seed);
PublicKey publicKey = augScheme.privateKeyToPublicKey(privateKey);

Bytes message = Bytes.of(1, 2, 3, 4, 5);  // Message is passed in as a bytes
Signature signature = augScheme.sign(privateKey, message);

// Verify the signature
boolean ok = augScheme.verify(publicKey, message, signature);
```

## Serializing keys and signatures to bytes example

```java
Bytes32 privateKeyBytes = privateKey.serialize();
Bytes48 publicKeyBytes = publicKey.serialize();
Bytes signatureBytes = signature.serialize();

System.out.println(privateKeyBytes.toHexString());  // 32 bytes printed in hex
System.out.println(publicKeyBytes.toHexString());   // 48 bytes printed in hex
System.out.println(signatureBytes.toHexString());   // 96 bytes printed in hex
```

## Loading keys and signatures from bytes example

```java
// Takes Bytes32
PrivateKey privateKey = PrivateKey.fromBytes(privateKeyBytes);
PrivateKey privateKey = PrivateKey.fromBytesModOrder(privateKeyBytes);

// Takes Bytes48
PublicKey publicKey = PublicKey.fromBytes(publicKeyBytes);

// Takes Bytes of length 96
Signature signature = Signature.fromBytes(signatureBytes);
```

## Create aggregate signatures example

```java
// Update seed to generate privateKey1
seed = Bytes.concatenate(Bytes.of(1), seed.slice(1, seed.size() - 1));
PrivateKey privateKey1 = MessageAugmentationSignatureScheme.keygen(seed);

// Update seed again to generate privateKey2
seed = Bytes.concatenate(Bytes.of(2), seed.slice(1, seed.size() - 1));
PrivateKey privateKey2 = MessageAugmentationSignatureScheme.keygen(seed);

// Create message to sign
Bytes message2 = Bytes.of(1, 2, 3, 4, 5, 6, 7);

// Generate first sigmature
PublicKey publicKey1 = privateKey1.getPublicKey();
Signature signature1 = augScheme.sign(privateKey1, message);

// Generate second sigmature
PublicKey publicKey2 = privateKey2.getPublicKey();
Signature signature2 = augScheme.sign(privateKey2, message2);

// Signatures can be non-interactively combined by anyone
Signature aggSig = augScheme.aggregateSignatures(List.of(signature1, signature2));

boolean ok = augScheme.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message2), aggSig)
```

## Arbitrary trees of aggregates example

```java
Bytes seed = Bytes.concatenate(Bytes.of(3), seed.slice(1, seed.size() - 1));
PrivateKey privateKey3 = MessageAugmentationSignatureScheme.keygen(seed);
PublicKey publicKey3 = privateKey3.getPublicKey();
Bytes message3 = Bytes.of(100, 2, 254, 88, 90, 45, 23);
Signature signature3 = augScheme.sign(privateKey3, message3);

Signature aggSigFinal = augScheme.aggregateSignatures(List.of(aggSig, signature3));
boolean ok = augScheme.aggregateVerify(List.of(publicKey1, publicKey2, publicKey3), List.of(message, message2, message3), aggSigFinal);
```

## Very fast verification with Proof of Possession scheme example

```java
// If the same message is signed, you can use Proof of Posession (PopScheme) for efficiency
// A proof of possession MUST be passed around with the PK to ensure security.
Signature popSignature1 = popScheme.sign(privateKey1, message);
Signature popSignature2 = popScheme.sign(privateKey2, message);
Signature popSignature3 = popScheme.sign(privateKey3, message);
Signature pop1 = popScheme.popProve(privateKey1);
Signature pop2 = popScheme.popProve(privateKey2);
Signature pop3 = popScheme.popProve(privateKey3);

boolean ok = popScheme.popVerify(publicKey1, pop1);
boolean ok = popScheme.popVerify(publicKey2, pop2);
boolean ok = popScheme.popVerify(publicKey3, pop3);
Signature popAggregatedSignature = popScheme.aggregateSignatures(List.of(popSignature1, popSignature2, popSignature3));

boolean ok = popScheme.fastAggregateVerify(List.of(publicKey1, publicKey2, publicKey3), message, popAggregatedSignature);

// Aggregate public key, indistinguishable from a single public key
PublicKey popAggregatedPk = publicKey1.add(publicKey2).add(publicKey3);
boolean ok = popScheme.verify(popAggregatedPk, message, popAggregatedSignature);

// Aggregate private keys
PrivateKey aggregatedPrivateKey = PrivateKey.aggregate(List.of(privateKey1, privateKey2, privateKey3));
boolean ok = popAggregatedSignature, popScheme.sign(aggregatedPrivateKey, message);
```

## HD keys using [EIP-2333](https://github.com/ethereum/EIPs/pull/2333) example

```java
// You can derive 'child' keys from any key, to create arbitrary trees. 4 byte indeces are used.
// Hardened (more secure, but no parent pk -> child pk)
PrivateKey masterPrivateKey = MessageAugmentationSignatureScheme.keygen(seed);

// Unhardened (less secure, but can go from parent pk -> child pk), BIP32 style
PublicKey masterPublicKey = masterPrivateKey.getPublicKey();
PrivateKey childUnhardenedPrivateKey = augScheme.deriveChildPrivateKeyUnhardened(masterPrivateKey, UInt32.valueOf(22));
PrivateKey grandchildUnhardenedPrivateKey = augScheme.deriveChildPrivateKeyUnhardened(childUnhardenedPrivateKey, UInt32.valueOf(0));
PublicKey childUnhardenedPublicKey = augScheme.deriveChildPublicKeyUnhardened(masterPublicKey, UInt32.valueOf(22));
PublicKey grandchildUnhardenedPublicKey = augScheme.deriveChildPublicKeyUnhardened(childUnhardenedPublicKey, UInt32.valueOf(0));
```


## BLST license

BLST is used with the
[Apache 2.0 license](https://github.com/supranational/blst/blob/master/LICENSE)