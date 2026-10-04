package surf.superhighway.bls;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.of;
import static surf.superhighway.bls.TestBytes.random;
import static surf.superhighway.bls.TestBytes.repeat;

class AggregateSignaturesTest {

    @Test
    void aggregatesWithAggregatePrivateKeyUsingBasicScheme() {
        byte[] message = of(100, 2, 254, 88, 90, 45, 23);
        BasicSignatureScheme basic = BasicSignatureScheme.getInstance();

        PrivateKey privateKey1 = PrivateKey.fromSeed(repeat(0x07, 32));
        PublicKey publicKey1 = privateKey1.getPublicKey();
        PrivateKey privateKey2 = PrivateKey.fromSeed(repeat(0x08, 32));
        PublicKey publicKey2 = privateKey2.getPublicKey();

        PrivateKey aggregatedPrivateKey1 = PrivateKey.aggregate(List.of(privateKey1, privateKey2));
        PrivateKey aggregatedPrivateKey2 = PrivateKey.aggregate(List.of(privateKey2, privateKey1));
        assertEquals(aggregatedPrivateKey1, aggregatedPrivateKey2);

        PublicKey aggregatedPublicKey = publicKey1.add(publicKey2);
        assertEquals(aggregatedPublicKey, aggregatedPrivateKey1.getPublicKey());

        Signature signature1 = basic.sign(privateKey1, message);
        Signature signature2 = basic.sign(privateKey2, message);
        Signature aggregatedSignature2 = basic.sign(aggregatedPrivateKey1, message);
        Signature aggregatedSignature = basic.aggregateSignatures(List.of(signature1, signature2));
        assertEquals(aggregatedSignature, aggregatedSignature2);

        // Verify as a single signature
        assertTrue(basic.verify(aggregatedPublicKey, message, aggregatedSignature));
        assertTrue(basic.verify(aggregatedPublicKey, message, aggregatedSignature2));

        // Aggregate verification with both keys fails since the messages are not distinct
        assertFalse(basic.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), aggregatedSignature));
        assertFalse(basic.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), aggregatedSignature2));

        // Distinct message, same private key
        byte[] message2 = of(200, 29, 54, 8, 9, 29, 155, 55);
        Signature signature3 = basic.sign(privateKey2, message2);
        Signature aggregatedSignatureFinal = basic.aggregateSignatures(List.of(aggregatedSignature, signature3));
        Signature aggregatedSignatureAlt = basic.aggregateSignatures(List.of(signature1, signature2, signature3));
        Signature aggregatedSignatureAlt2 = basic.aggregateSignatures(List.of(signature1, signature3, signature2));
        assertEquals(aggregatedSignatureFinal, aggregatedSignatureAlt);
        assertEquals(aggregatedSignatureFinal, aggregatedSignatureAlt2);

        PrivateKey finalPrivateKey1 = PrivateKey.aggregate(List.of(aggregatedPrivateKey1, privateKey2));
        PrivateKey finalPrivateKey2 = PrivateKey.aggregate(List.of(privateKey2, privateKey1, privateKey2));
        assertEquals(finalPrivateKey1, finalPrivateKey2);
        assertNotEquals(finalPrivateKey1, aggregatedPrivateKey1);

        PublicKey pkFinal = aggregatedPublicKey.add(publicKey2);
        PublicKey pkFinalAlt = publicKey2.add(publicKey1).add(publicKey2);
        assertEquals(pkFinal, pkFinalAlt);
        assertNotEquals(pkFinal, aggregatedPublicKey);

        assertTrue(basic.aggregateVerify(List.of(aggregatedPublicKey, publicKey2), List.of(message, message2), aggregatedSignatureFinal));
    }

    @Test
    void aggregatesWithAggregatePrivateKeyUsingAugScheme() {
        byte[] message = of(100, 2, 254, 88, 90, 45, 23);
        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();

        PrivateKey privateKey1 = PrivateKey.fromSeed(repeat(0x07, 32));
        PrivateKey privateKey2 = PrivateKey.fromSeed(repeat(0x08, 32));

        PrivateKey aggregatedPrivateKey1 = PrivateKey.aggregate(List.of(privateKey1, privateKey2));
        PrivateKey aggregatedPrivateKey2 = PrivateKey.aggregate(List.of(privateKey2, privateKey1));
        assertEquals(aggregatedPrivateKey1, aggregatedPrivateKey2);

        PublicKey aggregatedPublicKey = privateKey1.getPublicKey().add(privateKey2.getPublicKey());
        assertEquals(aggregatedPublicKey, aggregatedPrivateKey1.getPublicKey());

        // The aug scheme prepends the signer's key, so every signer must prepend the same
        // (aggregate) key for the signatures to aggregate over one message.
        Signature signature1 = aug.sign(privateKey1, message, aggregatedPublicKey);
        Signature signature2 = aug.sign(privateKey2, message, aggregatedPublicKey);
        Signature aggregatedSignature2 = aug.sign(aggregatedPrivateKey1, message, aggregatedPublicKey);

        Signature aggregatedSignature = aug.aggregateSignatures(List.of(signature1, signature2));
        assertEquals(aggregatedSignature, aggregatedSignature2);

        assertTrue(aug.verify(aggregatedPublicKey, message, aggregatedSignature));
        assertTrue(aug.verify(aggregatedPublicKey, message, aggregatedSignature2));
    }

    @Test
    void aggregatesWithMultipleLevelsAndDifferentMessages() {
        byte[] message1 = of(100, 2, 254, 88, 90, 45, 23);
        byte[] message2 = of(192, 29, 2, 0, 0, 45, 23);
        byte[] message3 = of(52, 29, 2, 0, 0, 45, 102);
        byte[] message4 = of(99, 29, 2, 0, 0, 45, 222);
        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();

        PrivateKey privateKey1 = PrivateKey.fromSeed(random(32));
        PrivateKey privateKey2 = PrivateKey.fromSeed(random(32));
        PublicKey publicKey1 = privateKey1.getPublicKey();
        PublicKey publicKey2 = privateKey2.getPublicKey();

        Signature aggregateL = aug.aggregateSignatures(List.of(aug.sign(privateKey1, message1), aug.sign(privateKey2, message2)));
        Signature aggregateR = aug.aggregateSignatures(List.of(aug.sign(privateKey2, message3), aug.sign(privateKey1, message4)));
        Signature aggregate = aug.aggregateSignatures(List.of(aggregateL, aggregateR));

        assertTrue(aug.aggregateVerify(List.of(publicKey1, publicKey2, publicKey2, publicKey1),
                List.of(message1, message2, message3, message4), aggregate));
    }

    @Test
    void aggregatesWithMultipleLevelsAndDegenerateMessages() {
        byte[] message = of(100, 2, 254, 88, 90, 45, 23);
        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();

        PrivateKey privateKey1 = PrivateKey.fromSeed(random(32));
        Signature aggregate = aug.sign(privateKey1, message);
        List<PublicKey> publicKeys = new ArrayList<>(List.of(privateKey1.getPublicKey()));
        List<byte[]> messages = new ArrayList<>(List.of(message));

        for (int i = 0; i < 10; i++) {
            PrivateKey privateKey = PrivateKey.fromSeed(random(32));
            publicKeys.add(privateKey.getPublicKey());
            messages.add(message);
            aggregate = aug.aggregateSignatures(List.of(aggregate, aug.sign(privateKey, message)));
        }
        assertTrue(aug.aggregateVerify(publicKeys, messages, aggregate));
    }

    @Test
    void augAggregatesManySignaturesWithDifferentMessages() {
        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();
        List<PublicKey> publicKeys = new ArrayList<>();
        List<Signature> signatures = new ArrayList<>();
        List<byte[]> messages = new ArrayList<>();

        for (int i = 0; i < 80; i++) {
            byte[] message = of(0, 100, 2, 45, 64, 12, 12, 63, i);
            PrivateKey privateKey = PrivateKey.fromSeed(random(32));
            publicKeys.add(privateKey.getPublicKey());
            signatures.add(aug.sign(privateKey, message));
            messages.add(message);
        }

        assertTrue(aug.aggregateVerify(publicKeys, messages, aug.aggregateSignatures(signatures)));
    }

    @Test
    void basicSchemeRejectsSameMessageButAugAndPopAccept() {
        byte[] message = of(100, 2, 254, 88, 90, 45, 23);
        PrivateKey privateKey1 = PrivateKey.fromSeed(repeat(0x50, 32));
        PrivateKey privateKey2 = PrivateKey.fromSeed(repeat(0x70, 32));
        PublicKey publicKey1 = privateKey1.getPublicKey();
        PublicKey publicKey2 = privateKey2.getPublicKey();

        BasicSignatureScheme basic = BasicSignatureScheme.getInstance();
        Signature basicAggregate = basic.aggregateSignatures(List.of(basic.sign(privateKey1, message), basic.sign(privateKey1, message)));
        assertFalse(basic.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), basicAggregate));

        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();
        Signature augAggregate = aug.aggregateSignatures(List.of(aug.sign(privateKey1, message), aug.sign(privateKey2, message)));
        assertTrue(aug.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), augAggregate));

        ProofOfPossessionSignatureScheme pop = ProofOfPossessionSignatureScheme.getInstance();
        Signature popAggregate = pop.aggregateSignatures(List.of(pop.sign(privateKey1, message), pop.sign(privateKey2, message)));
        assertTrue(pop.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), popAggregate));
    }

    @Test
    void aggregateOfSameSignatureVerifies() {
        byte[] message = of(100, 2, 254, 88, 90, 45, 23);
        PrivateKey privateKey = PrivateKey.fromSeed(repeat(0x50, 32));
        PublicKey publicKey = privateKey.getPublicKey();

        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();
        Signature signature = aug.sign(privateKey, message);
        Signature aggregate = aug.aggregateSignatures(List.of(signature, signature));
        assertTrue(aug.aggregateVerify(List.of(publicKey, publicKey), List.of(message, message), aggregate));
    }

    @Test
    void emptyAggregateVerifiesOnlyWithInfinity() {
        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();
        BasicSignatureScheme basic = BasicSignatureScheme.getInstance();
        ProofOfPossessionSignatureScheme pop = ProofOfPossessionSignatureScheme.getInstance();

        Signature aggregate = aug.aggregateSignatures(List.of(Signature.infinity()));
        assertEquals(Signature.infinity(), aggregate);
        assertEquals(Signature.infinity(), aug.aggregateSignatures(List.of()));

        assertTrue(aug.aggregateVerify(List.of(), List.of(), aggregate));
        assertTrue(basic.aggregateVerify(List.of(), List.of(), aggregate));
        assertFalse(pop.fastAggregateVerify(List.of(), new byte[0], aggregate));

        Signature notInfinity = basic.sign(PrivateKey.fromSeed(repeat(1, 32)), of(1));
        assertFalse(basic.aggregateVerify(List.of(), List.of(), notInfinity));
    }
}
