package surf.superhighway.bls;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.hex;
import static surf.superhighway.bls.TestBytes.of;
import static surf.superhighway.bls.TestBytes.random;
import static surf.superhighway.bls.TestBytes.repeat;

/** Key generation, serialization and group operations (ported from KeyGenTest, PrivateKeyTest, SignatureTest, PublicKeyTest). */
class KeysTest {

    @Test
    void keyGenerationVector() {
        byte[] seed = new byte[32];
        seed[31] = 0x08;
        PrivateKey sk = PrivateKey.fromSeed(seed);
        assertEquals("672165263b758015ebcc5273993d1ba7d778910effc81f2a9acf7a482180a989", hex(sk.toBytes()));

        PublicKey pk = sk.getPublicKey();
        assertEquals("8effb4415cc6d10a2d4006f342da08035731e1ffef53ebf98e1ad1702ecde3e3706c818abbb15f49c227daec9eb0bc11", hex(pk.toBytes()));
        assertEquals(1371335225L, pk.getFingerprint());
        assertEquals(0x51bcea39L, pk.getFingerprint());
    }

    @Test
    void keyGenerationVector2() {
        PublicKey pk = PrivateKey.fromSeed(repeat(8, 32)).getPublicKey();
        assertEquals(0x8ee7ba56L, pk.getFingerprint());
        assertEquals(2397551190L, pk.getFingerprint());
    }

    @Test
    void seedMustBeAtLeast32Bytes() {
        assertThrows(IllegalArgumentException.class, () -> PrivateKey.fromSeed(new byte[31]));
    }

    @Test
    void privateKeyEqualityAndCopy() {
        PrivateKey privateKey1 = PrivateKey.fromBytesModOrder(random(32));
        PrivateKey privateKey2 = PrivateKey.fromBytesModOrder(random(32));
        PrivateKey privateKey3 = privateKey1.copy();
        PrivateKey privateKey4 = privateKey2.copy();

        assertNotEquals(privateKey1, privateKey2);
        assertEquals(privateKey3, privateKey1);
        assertEquals(privateKey2, privateKey4);
        assertEquals(privateKey1.hashCode(), privateKey3.hashCode());
    }

    @Test
    void privateKeySerializationRoundTrip() {
        PrivateKey privateKey1 = PrivateKey.fromBytesModOrder(random(32));
        assertEquals(privateKey1, PrivateKey.fromBytesModOrder(privateKey1.toBytes()));
        assertEquals(privateKey1, PrivateKey.fromBytes(privateKey1.toBytes()));
    }

    @Test
    void fromBytesRejectsValuesAboveGroupOrder() {
        byte[] keyData = PrivateKey.fromSeed(repeat(0x10, 32)).toBytes();
        keyData[0] = (byte) 0xFF;
        BlsException exception = assertThrows(BlsException.class, () -> PrivateKey.fromBytes(keyData));
        assertEquals(BlsException.Kind.SECRET_KEY_GROUP_ORDER, exception.getKind());
    }

    @Test
    void fromBytesModOrderReducesValuesAboveGroupOrder() {
        PrivateKey reduced = PrivateKey.fromBytesModOrder(repeat(0xff, 32));
        // 2^256 - 1 mod r
        assertEquals("1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffd", hex(reduced.toBytes()));
    }

    @Test
    void zeroKeySignsToInfinity() {
        PrivateKey zero = PrivateKey.fromBytes(new byte[32]);
        assertEquals(PublicKey.infinity(), zero.getPublicKey());
        assertEquals(Signature.infinity(), BasicSignatureScheme.getInstance().sign(zero, of(1, 2, 3)));
        assertEquals(Signature.infinity(), MessageAugmentationSignatureScheme.getInstance().sign(zero, of(1, 2, 3)));
    }

    @Test
    void serializationRoundTrips() {
        BasicSignatureScheme basic = BasicSignatureScheme.getInstance();
        byte[] message = of(1, 65, 254, 88, 90, 45, 22);

        PrivateKey privateKey = PrivateKey.fromSeed(repeat(0x40, 32));
        PublicKey publicKey = privateKey.getPublicKey();
        assertEquals(privateKey, PrivateKey.fromBytes(privateKey.toBytes()));

        PublicKey publicKey2 = PublicKey.fromBytes(publicKey.toBytes());
        assertEquals(publicKey, publicKey2);
        assertArrayEquals(publicKey.toBytes(), publicKey2.toBytes());

        Signature signature = basic.sign(privateKey, message);
        Signature signature2 = Signature.fromBytes(signature.toBytes());
        assertEquals(signature, signature2);
        assertArrayEquals(signature.toBytes(), signature2.toBytes());

        assertTrue(basic.verify(publicKey2, message, signature2));
    }

    @Test
    void equalityOfKeysAndSignatures() {
        BasicSignatureScheme basic = BasicSignatureScheme.getInstance();
        byte[] message = of(1, 65, 254, 88, 90, 45, 22);

        PrivateKey privateKey1 = PrivateKey.fromSeed(repeat(0x40, 32));
        PrivateKey privateKey2 = privateKey1.copy();
        PrivateKey privateKey3 = PrivateKey.fromSeed(repeat(0x50, 32));

        assertEquals(privateKey1, privateKey2);
        assertNotEquals(privateKey1, privateKey3);
        assertEquals(privateKey1.getPublicKey(), privateKey2.getPublicKey());
        assertNotEquals(privateKey1.getPublicKey(), privateKey3.getPublicKey());
        assertEquals(basic.sign(privateKey1, message), basic.sign(privateKey2, message));
        assertNotEquals(basic.sign(privateKey1, message), basic.sign(privateKey3, message));
    }

    @Test
    void publicKeyGroupOperations() {
        PublicKey publicKey1 = PrivateKey.fromBytesModOrder(random(32)).getPublicKey();
        PublicKey publicKey2 = PrivateKey.fromBytesModOrder(random(32)).getPublicKey();

        assertEquals(publicKey1, publicKey1.add(PublicKey.infinity()));
        assertEquals(publicKey2.add(publicKey1), publicKey1.add(publicKey2));
        assertEquals(PublicKey.infinity(), publicKey1.add(publicKey1.negate()));
        assertEquals(publicKey1.add(publicKey2), PublicKey.aggregate(List.of(publicKey1, publicKey2)));
        assertEquals(PublicKey.infinity(), PublicKey.aggregate(List.of()));
        assertTrue(PublicKey.generator().isValid());
        assertTrue(PublicKey.infinity().isInfinity());
    }

    @Test
    void signatureGroupOperations() {
        BasicSignatureScheme basic = BasicSignatureScheme.getInstance();
        Signature signature1 = basic.sign(PrivateKey.fromBytesModOrder(random(32)), of(1));
        Signature signature2 = basic.sign(PrivateKey.fromBytesModOrder(random(32)), of(2));

        assertEquals(signature1, signature1.add(Signature.infinity()));
        assertEquals(signature2.add(signature1), signature1.add(signature2));
        assertEquals(Signature.infinity(), signature1.add(signature1.negate()));
        assertTrue(Signature.generator().isValid());
        assertTrue(Signature.infinity().isInfinity());
    }

    @Test
    void scalarMultiplyMatchesKeyDerivation() {
        // G1 * k == public key of k, with k as big-endian bytes (chia-bls PublicKey::from_integer)
        PrivateKey sk = PrivateKey.fromSeed(repeat(0x11, 32));
        assertEquals(sk.getPublicKey(), PublicKey.generator().scalarMultiply(sk.toBytes()));
        assertEquals(PublicKey.generator().add(PublicKey.generator()), PublicKey.generator().scalarMultiply(of(2)));
        assertEquals(Signature.generator().add(Signature.generator()), Signature.generator().scalarMultiply(of(2)));
    }

    @Test
    void validPointsAreValid() {
        PrivateKey privateKey = PrivateKey.fromSeed(repeat(0x05, 32));
        assertTrue(privateKey.getPublicKey().isValid());
        assertTrue(MessageAugmentationSignatureScheme.getInstance().sign(privateKey, of(10, 11, 12)).isValid());
    }

    @Test
    void randomBytesAreRejectedAsSignature() {
        // A random encoding with the compression bit set is almost never a G2 point.
        byte[] bytes = random(96);
        bytes[0] = (byte) ((bytes[0] & 0x1f) | 0x80);
        assertThrows(IllegalArgumentException.class, () -> Signature.fromBytes(bytes));
    }

    @Test
    void publicKeyOutsideG1IsRejected() {
        byte[] notInG1 = hex("8d5d0fb73b9c92df4eab4216e48c3e358578b4cc30f82c268bd6fef3bd34b558628daf1afef798d4c3b0fcd8b28c8973");

        BlsException exception = assertThrows(BlsException.class, () -> PublicKey.fromBytes(notInG1));
        assertEquals(BlsException.Kind.INVALID_PUBLIC_KEY, exception.getKind());
        assertEquals("PublicKey is invalid (BLST ERROR: BLST_POINT_NOT_ON_CURVE)", exception.getMessage());

        PublicKey badPublicKey = PublicKey.fromBytesUnchecked(notInG1);
        assertFalse(badPublicKey.isValid());

        PrivateKey privateKey = PrivateKey.fromSeed(repeat(0x05, 32));
        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();
        byte[] message = of(10, 11, 12);
        Signature signature = aug.sign(privateKey, message);
        assertFalse(aug.verify(badPublicKey, message, signature));
        assertTrue(aug.verify(privateKey.getPublicKey(), message, signature));
    }

    @Test
    void wrongLengthsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> PrivateKey.fromBytes(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> PublicKey.fromBytes(new byte[47]));
        assertThrows(IllegalArgumentException.class, () -> Signature.fromBytes(new byte[95]));
        assertThrows(NullPointerException.class, () -> PublicKey.fromBytes(null));
    }
}
