package surf.superhighway.bls;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.of;

/** The README walkthrough (adapted from Chia's bls-signatures README). Keep the two in sync. */
class ReadmeExampleTest {

    @Test
    void readme() {
        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();
        ProofOfPossessionSignatureScheme pop = ProofOfPossessionSignatureScheme.getInstance();

        // Example seed, used to generate a private key. Always use a secure RNG with
        // sufficient entropy (at least 32 bytes).
        byte[] seed = of(0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192, 19, 18, 12, 89, 6, 220, 18, 102, 58, 209, 82, 12,
                62, 89, 110, 182, 9, 44, 20, 254, 22);

        try (PrivateKey privateKey = PrivateKey.fromSeed(seed)) {
            PublicKey publicKey = privateKey.getPublicKey();
            byte[] message = of(1, 2, 3, 4, 5);
            Signature signature = aug.sign(privateKey, message);

            // Round-trip through bytes
            publicKey = PublicKey.fromBytes(publicKey.toBytes());       // 48 bytes
            signature = Signature.fromBytes(signature.toBytes());       // 96 bytes
            assertTrue(aug.verify(publicKey, message, signature));
        }

        byte[] message = of(1, 2, 3, 4, 5);
        seed[0] = 1;
        PrivateKey secretKey1 = PrivateKey.fromSeed(seed);
        seed[0] = 2;
        PrivateKey secretKey2 = PrivateKey.fromSeed(seed);
        byte[] message2 = of(1, 2, 3, 4, 5, 6, 7);

        PublicKey publicKey1 = secretKey1.getPublicKey();
        Signature signature1 = aug.sign(secretKey1, message);
        PublicKey publicKey2 = secretKey2.getPublicKey();
        Signature signature2 = aug.sign(secretKey2, message2);

        // Signatures can be non-interactively combined by anyone
        Signature aggSig = aug.aggregateSignatures(List.of(signature1, signature2));
        assertTrue(aug.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message2), aggSig));

        seed[0] = 3;
        PrivateKey secretKey3 = PrivateKey.fromSeed(seed);
        PublicKey publicKey3 = secretKey3.getPublicKey();
        byte[] message3 = of(100, 2, 254, 88, 90, 45, 23);
        Signature signature3 = aug.sign(secretKey3, message3);

        // Arbitrary trees of aggregates
        Signature aggSigFinal = aug.aggregateSignatures(List.of(aggSig, signature3));
        assertTrue(aug.aggregateVerify(List.of(publicKey1, publicKey2, publicKey3), List.of(message, message2, message3), aggSigFinal));

        // Proof of possession: when everyone signs the same message. A proof of possession
        // MUST be passed around with each public key.
        Signature popSignature1 = pop.sign(secretKey1, message);
        Signature popSignature2 = pop.sign(secretKey2, message);
        Signature popSignature3 = pop.sign(secretKey3, message);
        assertTrue(pop.popVerify(publicKey1, pop.popProve(secretKey1)));
        assertTrue(pop.popVerify(publicKey2, pop.popProve(secretKey2)));
        assertTrue(pop.popVerify(publicKey3, pop.popProve(secretKey3)));

        Signature popAggregate = pop.aggregateSignatures(List.of(popSignature1, popSignature2, popSignature3));
        assertTrue(pop.fastAggregateVerify(List.of(publicKey1, publicKey2, publicKey3), message, popAggregate));

        // An aggregate public key is indistinguishable from a single public key
        PublicKey popAggregatePk = publicKey1.add(publicKey2).add(publicKey3);
        assertTrue(pop.verify(popAggregatePk, message, popAggregate));

        // Aggregate private keys
        try (PrivateKey aggregateKey = PrivateKey.aggregate(List.of(secretKey1, secretKey2, secretKey3))) {
            assertEquals(popAggregate, pop.sign(aggregateKey, message));
        }

        // HD keys: hardened (no public derivation) and unhardened (BIP32 style)
        try (PrivateKey master = PrivateKey.fromSeed(seed);
             PrivateKey child = master.deriveHardened(152);
             PrivateKey grandchild = child.deriveHardened(952);
             PrivateKey childU = master.deriveUnhardened(22);
             PrivateKey grandchildU = childU.deriveUnhardened(0)) {
            PublicKey childUPk = master.getPublicKey().deriveUnhardened(22);
            PublicKey grandchildUPk = childUPk.deriveUnhardened(0);
            assertEquals(grandchildUPk, grandchildU.getPublicKey());
            assertTrue(grandchild.getPublicKey().isValid());
        }

        secretKey1.destroy();
        secretKey2.destroy();
        secretKey3.destroy();
    }
}
