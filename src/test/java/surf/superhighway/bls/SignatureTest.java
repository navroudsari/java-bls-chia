package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.Bytes48;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class SignatureTest {

    SecureRandom secureRandom;

    public SignatureTest() {

        try {
            secureRandom = SecureRandom.getInstance("NativePRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void canCopy() {
        BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();
        Bytes message = Bytes.of(1, 65, 254, 88, 90, 45, 22);

        Bytes32 seed = Bytes32.repeat((byte) 0x30);
        PrivateKey privateKey = BasicSignatureScheme.keygen(seed);
        PublicKey publicKey = privateKey.getPublicKey();
        PrivateKey privateKeyCopy = privateKey.copy();


        Bytes32 privateKeyBytes = privateKeyCopy.serialize();
        PrivateKey privateKey2 = PrivateKey.fromBytes(privateKeyBytes);

        PublicKey publicKeyCopy = publicKey.copy();
        Signature signature = basicSchemeMPL.sign(privateKey2, message);
        Signature signatureCopy = signature.copy();

        assertTrue(basicSchemeMPL.verify(publicKeyCopy, message, signatureCopy));
    }

    @Test
    public void shouldSignWithZeroKey() {
        PrivateKey privateKey = PrivateKey.ZERO;
        BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();
        MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();
        assertEquals(privateKey.getPublicKey(), PublicKey.ZERO);  // Infinity
        assertEquals(basicSchemeMPL.sign(privateKey, Bytes.of(1, 2, 3)), Signature.ZERO);
        assertEquals(augSchemeMPL.sign(privateKey, Bytes.of(1, 2, 3)), Signature.ZERO);
        assertEquals(augSchemeMPL.sign(privateKey, Bytes.of(1, 2, 3)), Signature.ZERO);
    }

    @Test
    public void shouldUseEqualityOperators() {
        BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();

        Bytes message = Bytes.of(1, 65, 254, 88, 90, 45, 22);
        Bytes seed = Bytes.repeat((byte) 0x40, 32);
        Bytes seed2 = Bytes.repeat((byte) 0x50, 32);

        PrivateKey privateKey1 = BasicSignatureScheme.keygen(Bytes32.wrap(seed));
        PrivateKey privateKey2 = privateKey1.copy();
        PrivateKey privateKey3 = BasicSignatureScheme.keygen(Bytes32.wrap(seed2));
        PublicKey publicKey1 = privateKey1.getPublicKey();
        PublicKey publicKey2 = privateKey2.getPublicKey();
        PublicKey publicKey3 = publicKey2.copy();
        PublicKey publicKey4 = privateKey3.getPublicKey();
        Signature signature1 = basicSchemeMPL.sign(privateKey1, message);
        Signature signature2 = basicSchemeMPL.sign(privateKey2, message);
        Signature signature3 = basicSchemeMPL.sign(privateKey2, message);
        Signature signature4 = basicSchemeMPL.sign(privateKey3, message);

        assertEquals(privateKey1, privateKey2);
        assertNotEquals(privateKey1, privateKey3);
        assertEquals(publicKey1, publicKey2);
        assertEquals(publicKey2, publicKey3);
        assertNotEquals(publicKey1, publicKey4);
        assertEquals(signature1, signature2);
        assertEquals(signature2, signature3);
        assertNotEquals(signature3, signature4);

        assertEquals(publicKey1.serialize(), publicKey2.serialize());
        assertEquals(signature1.serialize(), signature2.serialize());
    }

    @Test
    public void shouldSerializeAndDeserialize() {

        BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();
        Bytes message = Bytes.of(1, 65, 254, 88, 90, 45, 22);
        Bytes32 seed = Bytes32.wrap(Bytes.repeat((byte) 0x40, 32));

        PrivateKey privateKey1 = BasicSignatureScheme.keygen(seed);
        PublicKey publicKey = privateKey1.getPublicKey();
        Bytes32 privateKeyBytes = privateKey1.serialize();
        PrivateKey privateKey2 = PrivateKey.fromBytes(privateKeyBytes);
        assertEquals(privateKey1, privateKey2);

        Bytes48 publicKeyBytes = publicKey.serialize();
        PublicKey publicKey2 = PublicKey.fromBytes(publicKeyBytes);
        assertEquals(publicKey, publicKey2);

        Signature signature1 = basicSchemeMPL.sign(privateKey1, message);
        Bytes signatureBytes = signature1.serialize();
        Signature signature2 = Signature.fromBytes(signatureBytes);
        assertEquals(signature1, signature2);

        assertTrue(basicSchemeMPL.verify(publicKey2, message, signature2));
    }

    @Test
    public void ShouldNotVerifyAggregateWithSameMessageUnderBasicScheme() {
        Bytes message = Bytes.of(100, 2, 254, 88, 90, 45, 23);

        Bytes seed = Bytes32.repeat((byte) 0x50);
        Bytes seed2 = Bytes32.repeat((byte) 0x70);

        PrivateKey privateKey1 = BasicSignatureScheme.keygen(seed);
        PrivateKey privateKey2 = BasicSignatureScheme.keygen(seed2);

        PublicKey publicKey1 = privateKey1.getPublicKey();
        PublicKey publicKey2 = privateKey2.getPublicKey();

        BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();
        Signature signature1 = basicSchemeMPL.sign(privateKey1, message);
        Signature signature2 = basicSchemeMPL.sign(privateKey1, message);

        Signature aggregatedSignature = basicSchemeMPL.aggregateSignatures(List.of(signature1, signature2));

        assertFalse(basicSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), aggregatedSignature));
    }

    @Test
    public void shouldVerifyAggregateWithSameMessageUnderAugSchemeAndPopScheme() {
        Bytes message = Bytes.of(100, 2, 254, 88, 90, 45, 23);

        Bytes seed = Bytes32.repeat((byte) 0x50);
        Bytes seed2 = Bytes32.repeat((byte) 0x70);

        PrivateKey privateKey1 = BasicSignatureScheme.keygen(seed);
        PrivateKey privateKey2 = BasicSignatureScheme.keygen(seed2);

        PublicKey publicKey1 = privateKey1.getPublicKey();
        PublicKey publicKey2 = privateKey2.getPublicKey();

        MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();
        Signature augSignature1 = augSchemeMPL.sign(privateKey1, message);
        Signature augSignature2 = augSchemeMPL.sign(privateKey2, message);
        Signature aggregatedAugSignature = augSchemeMPL.aggregateSignatures(List.of(augSignature1, augSignature2));
        assertTrue(augSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), aggregatedAugSignature));

        ProofOfPossessionSignatureScheme popSchemeMPL = ProofOfPossessionSignatureScheme.getInstance();
        Signature popSignature1 = popSchemeMPL.sign(privateKey1, message);
        Signature popSignature2 = popSchemeMPL.sign(privateKey2, message);
        Signature aggregatedPopSignature = popSchemeMPL.aggregateSignatures(List.of(popSignature1, popSignature2));
        assertTrue(popSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message, message), aggregatedPopSignature));
    }

    @Test
    public void shouldAugAggregateManySignaturesWithDiffMessage() {
        List<PublicKey> publicKeys = new ArrayList<>();
        List<Signature> signatures = new ArrayList<>();
        List<Bytes> messages = new ArrayList<>();
        MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();

        for (int i = 0; i < 80; i++) {
            Bytes message = Bytes.of(0, 100, 2, 45, 64, 12, 12, 63, i);
            PrivateKey privateKey = BasicSignatureScheme.keygen(Bytes32.secure(secureRandom.generateSeed(32)));
            publicKeys.add(privateKey.getPublicKey());
            Signature signature = augSchemeMPL.sign(privateKey, message);
            signatures.add(signature);
            messages.add(message);
        }

        Signature aggregatedSignature = augSchemeMPL.aggregateSignatures(signatures);

        assertTrue(augSchemeMPL.aggregateVerify(publicKeys, messages, aggregatedSignature));
    }

    @Test
    public void aggregateVerificationOfZeroItemsWithInfinityShouldPass() {
        List<PublicKey> publicKeys = new ArrayList<>();
        List<Bytes> messages = new ArrayList<>();
        List<Signature> signatures = new ArrayList<>();

        MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();
        BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();
        ProofOfPossessionSignatureScheme popSchemeMPL = ProofOfPossessionSignatureScheme.getInstance();

        signatures.add(Signature.ZERO);
        Signature aggregatedSignature = augSchemeMPL.aggregateSignatures(signatures);

        assertNotEquals(aggregatedSignature.serialize().size(), 0);
        assertEquals(aggregatedSignature, Signature.ZERO);

        assertTrue(augSchemeMPL.aggregateVerify(publicKeys, messages, aggregatedSignature));
        assertTrue(basicSchemeMPL.aggregateVerify(publicKeys, messages, aggregatedSignature));

        Bytes message = Bytes.EMPTY;
        assertEquals(0, publicKeys.size());
        assertFalse(popSchemeMPL.fastAggregateVerify(publicKeys, message, aggregatedSignature));
    }

    @Test
    public void aggregateSameSignatureElement() {
        Bytes message = Bytes.of(100, 2, 254, 88, 90, 45, 23);

        Bytes seed = Bytes32.repeat((byte) 0x50);
        PrivateKey privateKey = BasicSignatureScheme.keygen(seed);
        PublicKey publicKey = privateKey.getPublicKey();

        MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();
        Signature augSignature = augSchemeMPL.sign(privateKey, message);
        Signature aggregatedAugSignature = augSchemeMPL.aggregateSignatures(List.of(augSignature, augSignature));
        assertTrue(augSchemeMPL.aggregateVerify(List.of(publicKey, publicKey), List.of(message, message), aggregatedAugSignature));
    }

    @Test
    public void invalidSignaturesShouldNotSucceed() {
        Bytes probablyInvalidSignatureBytes = Bytes.wrap(secureRandom.generateSeed(96));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> Signature.fromBytes(probablyInvalidSignatureBytes));
        assertEquals("Signature is invalid", exception.getMessage());
    }

    @Test
    public void validPointsShouldSucceed() {
        Bytes seed = Bytes32.repeat((byte) 0x05);
        Bytes message = Bytes.of(10, 11, 12);

        PrivateKey privateKey = BasicSignatureScheme.keygen(seed);
        PublicKey publicKey = BasicSignatureScheme.getInstance().privateKeyToPublicKey(privateKey);
        assertTrue(publicKey.isValid());

        Signature signature = MessageAugmentationSignatureScheme.getInstance().sign(privateKey, message);
        assertTrue(signature.isValid());
    }
}
