package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class AggregateSignaturesTest {

    SecureRandom secureRandom;

    public AggregateSignaturesTest() {
        try {
            secureRandom = SecureRandom.getInstance("NativePRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void shouldCreateAggregatesWithAggPrivateKeyUsingBasicScheme() {
        final Bytes message = Bytes.of(100, 2, 254, 88, 90, 45, 23);
        final Bytes seed1 = Bytes32.repeat((byte) 0x07);
        final Bytes seed2 = Bytes32.repeat((byte) 0x08);

        final BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();

        PrivateKey privateKey1 = BasicSignatureScheme.keygen(seed1);
        PublicKey publicKey1 = privateKey1.getPublicKey();

        PrivateKey privateKey2 = BasicSignatureScheme.keygen(seed2);
        PublicKey publicKey2 = privateKey2.getPublicKey();

        PrivateKey aggregatedPrivateKey1 = PrivateKey.aggregate(List.of(privateKey1, privateKey2));
        PrivateKey aggregatedPrivateKey2 = PrivateKey.aggregate(List.of(privateKey2, privateKey1));
        assertEquals(aggregatedPrivateKey1, aggregatedPrivateKey2);

        PublicKey aggregatedPublicKey = publicKey1.add(publicKey2);
        assertEquals(aggregatedPublicKey, aggregatedPrivateKey1.getPublicKey());

        Signature signature1 = basicSchemeMPL.sign(privateKey1, message);
        Signature signature2 = basicSchemeMPL.sign(privateKey2, message);

        Signature aggregatedSignature2 = basicSchemeMPL.sign(aggregatedPrivateKey1, message);

        Signature aggregatedSignature = basicSchemeMPL.aggregateSignatures(List.of(signature1, signature2));
        assertEquals(aggregatedSignature, aggregatedSignature2);

        // Verify as a single Signature
        assertTrue(basicSchemeMPL.verify(aggregatedPublicKey, message, aggregatedSignature));
        assertTrue(basicSchemeMPL.verify(aggregatedPublicKey, message, aggregatedSignature2));

        // Verify aggregate with both keys (Fails since not distinct)
        assertFalse(basicSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), aggregatedSignature));
        assertFalse(basicSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), aggregatedSignature2));

        // Try the same with distinct message, and same privateKey
        Bytes message2 = Bytes.of(200, 29, 54, 8, 9, 29, 155, 55);
        Signature signatures3 = basicSchemeMPL.sign(privateKey2, message2);
        Signature aggregatedSignatureFinal = basicSchemeMPL.aggregateSignatures(List.of(aggregatedSignature, signatures3));
        Signature aggregatedSignatureAlt = basicSchemeMPL.aggregateSignatures(List.of(signature1, signature2, signatures3));
        Signature aggregatedSignatureAlt2 = basicSchemeMPL.aggregateSignatures(List.of(signature1, signatures3, signature2));
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

        // Cannot verify with aggregatedPublicKey (since we have multiple messages)
        assertTrue(basicSchemeMPL.aggregateVerify(List.of(aggregatedPublicKey, publicKey2), List.of(message, message2), aggregatedSignatureFinal));
    }

    @Test
    public void shouldCreateAggregatesWithAggregatePrivateKeyUsingAugScheme() {
        final Bytes message = Bytes.of(100, 2, 254, 88, 90, 45, 23);
        final Bytes seed1 = Bytes32.repeat((byte) 0x07);
        final Bytes seed2 = Bytes32.repeat((byte) 0x08);

        final MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();

        PrivateKey privateKey1 = MessageAugmentationSignatureScheme.keygen(seed1);
        PublicKey publicKey1 = privateKey1.getPublicKey();

        PrivateKey privateKey2 = MessageAugmentationSignatureScheme.keygen(seed2);
        PublicKey publicKey2 = privateKey2.getPublicKey();

        PrivateKey aggregatedPrivateKey1 = PrivateKey.aggregate(List.of(privateKey1, privateKey2));
        PrivateKey aggregatedPrivateKey2 = PrivateKey.aggregate(List.of(privateKey2, privateKey1));
        assertEquals(aggregatedPrivateKey1, aggregatedPrivateKey2);

        PublicKey aggregatedPublicKey = publicKey1.add(publicKey2);
        assertEquals(aggregatedPublicKey, aggregatedPrivateKey1.getPublicKey());

        //
        // Note, AugScheme will automatically prepend the public key of the
        // provided private key to the message before signing. This creates
        // problems in aggregation here as then the messages are all technically
        // different so the aggregation doesn't work as expected. So you must
        // specify directly the same public key (PublicKey) for all messages.
        // Here we use the Aggregate Public Key, however, you can use any
        // PublicKey as long as there are all the same.
        //
        Signature signature1 = augSchemeMPL.sign(privateKey1, message, aggregatedPublicKey);
        Signature signature2 = augSchemeMPL.sign(privateKey2, message, aggregatedPublicKey);

        // Technically passing in aggregatedPublicKey is unneeded, but kept for clarity
        Signature aggregatedSignature2 = augSchemeMPL.sign(aggregatedPrivateKey1, message, aggregatedPublicKey);

        Signature aggregatedSignature = augSchemeMPL.aggregateSignatures(List.of(signature1, signature2));
        assertEquals(aggregatedSignature, aggregatedSignature2);

        // Verify as a single Signature
        assertTrue(augSchemeMPL.verify(aggregatedPublicKey, message, aggregatedSignature));
        assertTrue(augSchemeMPL.verify(aggregatedPublicKey, message, aggregatedSignature2));
    }

    @Test
    public void shouldAggregateWithMultipleLevelsAndDifferentMessages() {
        final Bytes message1 = Bytes.of(100, 2, 254, 88, 90, 45, 23);
        final Bytes message2 = Bytes.of(192, 29, 2, 0, 0, 45, 23);
        final Bytes message3 = Bytes.of(52, 29, 2, 0, 0, 45, 102);
        final Bytes message4 = Bytes.of(99, 29, 2, 0, 0, 45, 222);

        final MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();

        PrivateKey privateKey1 = MessageAugmentationSignatureScheme.keygen(Bytes.secure(secureRandom.generateSeed(32)));
        PrivateKey privateKey2 = MessageAugmentationSignatureScheme.keygen(Bytes.secure(secureRandom.generateSeed(32)));

        PublicKey publicKey1 = privateKey1.getPublicKey();
        PublicKey publicKey2 = privateKey2.getPublicKey();

        Signature signature1 = augSchemeMPL.sign(privateKey1, message1);
        Signature signature2 = augSchemeMPL.sign(privateKey2, message2);
        Signature signatures3 = augSchemeMPL.sign(privateKey2, message3);
        Signature signatures4 = augSchemeMPL.sign(privateKey1, message4);

        List<Signature> signaturesL = List.of(signature1, signature2);
        Signature aggregatedSignaturesL = augSchemeMPL.aggregateSignatures(signaturesL);

        List<Signature> signaturesR = List.of(signatures3, signatures4);
        Signature aggregatedSignaturesR = augSchemeMPL.aggregateSignatures(signaturesR);

        List<Signature> signatures = List.of(aggregatedSignaturesL, aggregatedSignaturesR);
        Signature aggregatedSignature = augSchemeMPL.aggregateSignatures(signatures);

        List<PublicKey> allPublicKeys = List.of(publicKey1, publicKey2, publicKey2, publicKey1);
        List<Bytes> allMessages = List.of(message1, message2, message3, message4);
        assertTrue(augSchemeMPL.aggregateVerify(allPublicKeys, allMessages, aggregatedSignature));
    }

    @Test
    public void shouldAggregateWithMultipleLevelsAndDegenerate() {
        final Bytes message1 = Bytes.of(100, 2, 254, 88, 90, 45, 23);

        final MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();

        PrivateKey privateKey1 = MessageAugmentationSignatureScheme.keygen(Bytes.secure(secureRandom.generateSeed(32)));
        PublicKey publicKey1 = privateKey1.getPublicKey();
        Signature aggregatedSignature = augSchemeMPL.sign(privateKey1, message1);
        List<PublicKey> publicKeys = new ArrayList<>();
        publicKeys.add(publicKey1);
        List<Bytes> messages = new ArrayList<>();
        messages.add(message1);

        for (int i = 0; i < 10; i++) {
            PrivateKey privateKey = MessageAugmentationSignatureScheme.keygen(Bytes.secure(secureRandom.generateSeed(32)));
            PublicKey publicKey = privateKey.getPublicKey();
            publicKeys.add(publicKey);
            messages.add(message1);
            Signature signature = augSchemeMPL.sign(privateKey, message1);
            aggregatedSignature = augSchemeMPL.aggregateSignatures(List.of(aggregatedSignature, signature));
        }
        assertTrue(augSchemeMPL.aggregateVerify(publicKeys, messages, aggregatedSignature));
    }
}
