package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.Assert.*;

public class PrivateKeyTest {

    SecureRandom secureRandom;

    public PrivateKeyTest() {

        try {
            secureRandom = SecureRandom.getInstance("NativePRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testPrivateKeyEquality() {

        PrivateKey privateKey1 = PrivateKey.fromBytesModOrder(Bytes32.secure(secureRandom.generateSeed(32)));
        PrivateKey privateKey2 = PrivateKey.fromBytesModOrder(Bytes32.secure(secureRandom.generateSeed(32)));
        PrivateKey privateKey3 = privateKey1.copy();
        PrivateKey privateKey4 = privateKey2.copy();

        assertNotEquals(privateKey1, privateKey2);
        assertNotEquals(privateKey1, privateKey2);
        assertEquals(privateKey3, privateKey1);
        assertEquals(privateKey2, privateKey4);
    }

    @Test
    public void testSerializationDeserialization() {
        PrivateKey privateKey1 = PrivateKey.fromBytesModOrder(Bytes32.secure(secureRandom.generateSeed(32)));
        Bytes32 buffer = privateKey1.serialize();
        PrivateKey privateKey2 = PrivateKey.fromBytesModOrder(buffer);
        assertEquals(privateKey1, privateKey2);
    }

    @Test
    public void testExceptionOnInvalidPrivateKey() {
        PrivateKey privateKey = BasicSignatureScheme.keygen(Bytes32.repeat((byte) 0x10));
        byte[] keyData = privateKey.serialize().toArray();
        keyData[0] = (byte) 0xFF;
        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> PrivateKey.fromBytes(Bytes32.wrap(keyData)));
        assertEquals("PrivateKey byte data must be less than the group order", exception.getMessage());
    }

    @Test
    public void testPublicKeyOperations() {
        PublicKey publicKey1 = PrivateKey.fromBytesModOrder(Bytes32.secure(secureRandom.generateSeed(32))).getPublicKey();
        PublicKey publicKey2 = PrivateKey.fromBytesModOrder(Bytes32.secure(secureRandom.generateSeed(32))).getPublicKey();

        PublicKey result = publicKey1.add(PublicKey.ZERO);
        assertEquals(publicKey1, result);
        assertEquals(publicKey1, publicKey1.add(PublicKey.ZERO));
        assertEquals(publicKey2.add(publicKey1), publicKey1.add(publicKey2));

        publicKey1 = publicKey1.add(publicKey1.negate());
        assertEquals(PublicKey.ZERO, publicKey1);

        PublicKey generatedPublicKey = PublicKey.generate();
        assertTrue(generatedPublicKey.isValid());
    }

    @Test
    public void testSignatureOperations() {
        Signature signature1 = PrivateKey.fromBytesModOrder(Bytes32.secure(secureRandom.generateSeed(32))).getSignature();
        Signature signature2 = PrivateKey.fromBytesModOrder(Bytes32.secure(secureRandom.generateSeed(32))).getSignature();

        Signature result = signature1.add(Signature.ZERO);
        assertEquals(signature1, result);
        assertEquals(signature1, signature1.add(Signature.ZERO));
        assertEquals(signature2.add(signature1), signature1.add(signature2));

        signature1 = signature1.add(signature1.negate());
        assertEquals(Signature.ZERO, signature1);

        Signature generatedSignature = Signature.generate();
        assertTrue(generatedSignature.isValid());
    }
}
