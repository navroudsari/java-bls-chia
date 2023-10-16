package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes48;
import org.apache.tuweni.units.bigints.UInt32;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ChiaReadmeExampleTest {

    @Test
    public void readmeTest() {
        MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();
        ProofOfPossessionSignatureScheme popSchemeMPL = ProofOfPossessionSignatureScheme.getInstance();

        // Example seed, used to generate private key. Always use
        // a secure RNG with sufficient entropy to generate a seed (at least 32
        // bytes).
        Bytes seed = Bytes.of(0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192, 19, 18, 12, 89, 6, 220, 18, 102, 58, 209, 82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22);

        PrivateKey privateKey = MessageAugmentationSignatureScheme.keygen(seed);
        PublicKey publicKey = privateKey.getPublicKey();

        Bytes message = Bytes.of(1, 2, 3, 4, 5);  // Message is passed in as a byte vector
        Signature signature = augSchemeMPL.sign(privateKey, message);

        Bytes48 publicKeyBytes = publicKey.serialize();
        Bytes signatureBytes = signature.serialize();

        // Takes array of 48 bytes
        publicKey = PublicKey.fromBytes(publicKeyBytes);

        // Takes array of 96 bytes
        signature = Signature.fromBytes(signatureBytes);

        assertTrue(augSchemeMPL.verify(publicKey, message, signature));

        // Generate some more private keys
        seed = Bytes.concatenate(Bytes.of(1), seed.slice(1, seed.size() - 1));
        PrivateKey secretKey1 = MessageAugmentationSignatureScheme.keygen(seed);
        seed = Bytes.concatenate(Bytes.of(2), seed.slice(1, seed.size() - 1));
        PrivateKey secretKey2 = MessageAugmentationSignatureScheme.keygen(seed);
        Bytes message2 = Bytes.of(1, 2, 3, 4, 5, 6, 7);

        // Generate first sig
        PublicKey publicKey1 = secretKey1.getPublicKey();
        Signature signature1 = augSchemeMPL.sign(secretKey1, message);

        // Generate second sig
        PublicKey publicKey2 = secretKey2.getPublicKey();
        Signature signature2 = augSchemeMPL.sign(secretKey2, message2);

        // Signatures can be non interactively combined by anyone
        Signature aggSig = augSchemeMPL.aggregateSignatures(List.of(signature1, signature2));

        assertTrue(augSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message2), aggSig));

        seed = Bytes.concatenate(Bytes.of(3), seed.slice(1, seed.size() - 1));
        PrivateKey secretKey3 = MessageAugmentationSignatureScheme.keygen(seed);
        PublicKey publicKey3 = secretKey3.getPublicKey();
        Bytes message3 = Bytes.of(100, 2, 254, 88, 90, 45, 23);
        Signature signature3 = augSchemeMPL.sign(secretKey3, message3);

        // Arbitrary trees of aggregates
        Signature aggSigFinal = augSchemeMPL.aggregateSignatures(List.of(aggSig, signature3));

        assertTrue(augSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2, publicKey3), List.of(message, message2, message3), aggSigFinal));

        // If the same message is signed, you can use Proof of Possession
        // (PopScheme) for efficiency A proof of possession MUST be passed
        // around with the PK to ensure security.

        Signature popSignature1 = popSchemeMPL.sign(secretKey1, message);
        Signature popSignature2 = popSchemeMPL.sign(secretKey2, message);
        Signature popSignature3 = popSchemeMPL.sign(secretKey3, message);
        Signature pop1 = popSchemeMPL.popProve(secretKey1);
        Signature pop2 = popSchemeMPL.popProve(secretKey2);
        Signature pop3 = popSchemeMPL.popProve(secretKey3);

        assertTrue(popSchemeMPL.popVerify(publicKey1, pop1));
        assertTrue(popSchemeMPL.popVerify(publicKey2, pop2));
        assertTrue(popSchemeMPL.popVerify(publicKey3, pop3));
        Signature popAggregatedSignature = popSchemeMPL.aggregateSignatures(List.of(popSignature1, popSignature2, popSignature3));

        assertTrue(popSchemeMPL.fastAggregateVerify(List.of(publicKey1, publicKey2, publicKey3), message, popAggregatedSignature));

        // Aggregate public key, indistinguishable from a single public key
        PublicKey popAggregatedPk = publicKey1.add(publicKey2).add(publicKey3);
        assertTrue(popSchemeMPL.verify(popAggregatedPk, message, popAggregatedSignature));

        // Aggregate private keys
        PrivateKey aggregatedPrivateKey = PrivateKey.aggregate(List.of(secretKey1, secretKey2, secretKey3));
        assertEquals(popAggregatedSignature, popSchemeMPL.sign(aggregatedPrivateKey, message));

        PrivateKey masterPrivateKey = MessageAugmentationSignatureScheme.keygen(seed);

        PublicKey masterPublicKey = masterPrivateKey.getPublicKey();
        PrivateKey childUnhardenedPrivateKey = augSchemeMPL.deriveChildPrivateKeyUnhardened(masterPrivateKey, UInt32.valueOf(22));
        PrivateKey grandchildUnhardenedPrivateKey = augSchemeMPL.deriveChildPrivateKeyUnhardened(childUnhardenedPrivateKey, UInt32.valueOf(0));

        PublicKey childUnhardenedPublicKey = augSchemeMPL.deriveChildPublicKeyUnhardened(masterPublicKey, UInt32.valueOf(22));
        PublicKey grandchildUnhardenedPublicKey = augSchemeMPL.deriveChildPublicKeyUnhardened(childUnhardenedPublicKey, UInt32.valueOf(0));

        assertEquals(grandchildUnhardenedPublicKey, grandchildUnhardenedPrivateKey.getPublicKey());
    }
}
