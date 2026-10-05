package surf.superhighway.bls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.hex;

/**
 * Port of the tests in chia_rs {@code crates/chia-bls/src/public_key.rs} (chia_rs 6485640).
 * Rust's seeded {@code StdRng} is replaced by {@code java.util.Random(1337)}: the inputs differ,
 * but each test checks a property that holds for any input.
 */
class RustPublicKeyTest {

    private static final String SK_HEX = "52d75c4707e39595b27314547f9723e5530c01198af3fc5849d9a7af65631efb";

    private static byte[] fill(Random rng, int length) {
        byte[] out = new byte[length];
        rng.nextBytes(out);
        return out;
    }

    /** 32 random bytes with a zero top byte, so the integer is below the group order. */
    private static byte[] smallInteger(Random rng) {
        byte[] data = fill(rng, 32);
        data[0] = 0;
        return data;
    }

    @Test
    void testDeriveUnhardened() {
        PrivateKey sk = PrivateKey.fromBytes(hex(SK_HEX));
        PublicKey pk = sk.getPublicKey();
        for (int idx = 0; idx < 4; idx++) {
            assertEquals(hex(sk.deriveUnhardened(idx).getPublicKey().toBytes()), hex(pk.deriveUnhardened(idx).toBytes()));
        }
    }

    @Test
    void testFromBytes() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            byte[] data = fill(rng, 48);
            data[0] = (byte) 0x80;   // clear the bits that mean infinity
            BlsException e = assertThrows(BlsException.class, () -> PublicKey.fromBytes(data));
            assertEquals(BlsException.Kind.INVALID_PUBLIC_KEY, e.getKind());
            assertTrue(List.of(BlstError.BLST_BAD_ENCODING, BlstError.BLST_POINT_NOT_ON_CURVE).contains(e.getBlstError()),
                    e.getMessage());
        }
    }

    @ParameterizedTest
    @CsvSource({
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001, G1_NOT_CANONICAL",
            "c08000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, G1_NOT_CANONICAL",
            "c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, G1_NOT_CANONICAL",
            "e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, G1_NOT_CANONICAL",
            "d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, G1_NOT_CANONICAL",
            "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, G1_INFINITY_NOT_ZERO",
            "400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, G1_INFINITY_INVALID_BITS",
    })
    void testFromBytesFailures(String input, BlsException.Kind kind) {
        BlsException e = assertThrows(BlsException.class, () -> PublicKey.fromBytes(hex(input)));
        assertEquals(kind, e.getKind());
        assertNull(e.getBlstError());
    }

    @Test
    void testFromBytesInfinity() {
        byte[] bytes = hex("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assertEquals(PublicKey.infinity(), PublicKey.fromBytes(bytes));
    }

    @Test
    void testGetFingerprint() {
        PublicKey pk = PublicKey.fromBytes(hex("997cc43ed8788f841fcf3071f6f212b89ba494b6ebaf1bda88c3f9de9d968a61f3b7284a5ee13889399ca71a026549a2"));
        assertEquals(651_010_559L, pk.getFingerprint());
    }

    @Test
    void testAggregatePubkey() {
        PublicKey pk = PrivateKey.fromBytes(hex(SK_HEX)).getPublicKey();
        PublicKey pk2 = pk.add(pk);
        PublicKey pk3 = pk.add(pk).add(pk);

        assertEquals(PublicKey.fromBytes(hex("b1b8033286299e7f238aede0d3fea48d133a1e233139085f72c102c2e6cc1f8a4ea64ed2838c10bbd2ef8f78ef271bf3")), pk2);
        assertEquals(PublicKey.fromBytes(hex("a8bc2047d90c04a12e8c38050ec0feb4417b4d5689165cd2cea8a7903aad1778e36548a46d427b5ec571364515e456d6")), pk3);
    }

    @Test
    void testRoundtrip() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            PublicKey pk = PrivateKey.fromSeed(fill(rng, 32)).getPublicKey();
            assertEquals(pk, PublicKey.fromBytes(pk.toBytes()));
        }
    }

    @Test
    void testDefaultIsValid() {
        assertTrue(PublicKey.infinity().isValid());
    }

    @Test
    void testInfinityIsValid() {
        byte[] data = new byte[48];
        data[0] = (byte) 0xc0;
        assertTrue(PublicKey.fromBytes(data).isValid());
    }

    @Test
    void testIsValid() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            assertTrue(PrivateKey.fromSeed(fill(rng, 32)).getPublicKey().isValid());
        }
    }

    @Test
    void testDefaultIsInf() {
        assertTrue(PublicKey.infinity().isInfinity());
    }

    @Test
    void testInfinity() {
        byte[] data = new byte[48];
        data[0] = (byte) 0xc0;
        assertTrue(PublicKey.fromBytes(data).isInfinity());
    }

    @Test
    void testIsInf() {
        Random rng = new Random(1337);
        for (int i = 0; i < 500; i++) {
            assertFalse(PrivateKey.fromSeed(fill(rng, 32)).getPublicKey().isInfinity());
        }
    }

    @Test
    void testHash() {
        Random rng = new Random(1337);
        PublicKey pk1 = PrivateKey.fromSeed(fill(rng, 32)).getPublicKey();
        PublicKey pk2 = pk1.deriveUnhardened(1);
        PublicKey pk3 = pk1.deriveUnhardened(2);

        assertNotEquals(pk2.hashCode(), pk3.hashCode());
        assertEquals(pk1.deriveUnhardened(42).hashCode(), pk1.deriveUnhardened(42).hashCode());
    }

    @Test
    void testDebug() {
        byte[] data = new byte[48];
        data[0] = (byte) 0xc0;
        assertEquals("<G1Element " + hex(data) + ">", PublicKey.fromBytes(data).toString());
    }

    @Test
    void testGenerator() {
        assertEquals("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
                hex(PublicKey.generator().toBytes()));
    }

    @Test
    void testFromInteger() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            byte[] data = smallInteger(rng);
            assertEquals(PrivateKey.fromBytes(data).getPublicKey(), PublicKey.fromInteger(data));
        }
    }

    // test cases from zksnark test in chia_rs
    @ParameterizedTest
    @CsvSource({
            "06f6ba2972ab1c83718d747b2d55cca96d08729b1ea5a3ab3479b8efe2d455885abf65f58d1507d7f260cd2a4687db821171c9d8dc5c0f5c3c4fd64b26cf93ff28b2e683c409fb374c4e26cc548c6f7cef891e60b55e6115bb38bbe97822e4d4, a6f6ba2972ab1c83718d747b2d55cca96d08729b1ea5a3ab3479b8efe2d455885abf65f58d1507d7f260cd2a4687db82",
            "127271e81a1cb5c08a68694fcd5bd52f475d545edd4fbd49b9f6ec402ee1973f9f4102bf3bfccdcbf1b2f862af89a1340d40795c1c09d1e10b1acfa0f3a97a71bf29c11665743fa8d30e57e450b8762959571d6f6d253b236931b93cf634e7cf, b27271e81a1cb5c08a68694fcd5bd52f475d545edd4fbd49b9f6ec402ee1973f9f4102bf3bfccdcbf1b2f862af89a134",
            "0fe94ac2d68d39d9207ea0cae4bb2177f7352bd754173ed27bd13b4c156f77f8885458886ee9fbd212719f27a96397c110fa7b4f898b1c45c2e82c5d46b52bdad95cae8299d4fd4556ae02baf20a5ec989fc62f28c8b6b3df6dc696f2afb6e20, afe94ac2d68d39d9207ea0cae4bb2177f7352bd754173ed27bd13b4c156f77f8885458886ee9fbd212719f27a96397c1",
            "13aedc305adfdbc854aa105c41085618484858e6baa276b176fd89415021f7a0c75ff4f9ec39f482f142f1b54c11144815e519df6f71b1db46c83b1d2bdf381fc974059f3ccd87ed5259221dc37c50c3be407b58990d14b6d5bb79dad9ab8c42, b3aedc305adfdbc854aa105c41085618484858e6baa276b176fd89415021f7a0c75ff4f9ec39f482f142f1b54c111448",
    })
    void testFromUncompressed(String input, String expect) {
        assertEquals(expect, hex(PublicKey.fromUncompressed(hex(input)).toBytes()));
    }

    @Test
    void testNegateRoundtrip() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            PublicKey g1 = PublicKey.fromInteger(smallInteger(rng));
            PublicKey g1Neg = g1.negate();
            assertNotEquals(g1, g1Neg);
            assertEquals(g1, g1Neg.negate());
        }
    }

    @Test
    void testNegateInfinity() {
        // negate on infinity is a no-op
        assertEquals(PublicKey.infinity(), PublicKey.infinity().negate());
    }

    @Test
    void testNegate() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            PublicKey g1 = PublicKey.fromInteger(smallInteger(rng));
            PublicKey g1Neg = g1.negate();
            // adding the negative undoes adding the positive
            PublicKey g1Double = g1.add(g1);
            assertNotEquals(g1, g1Double);
            assertEquals(g1, g1Double.add(g1Neg));
        }
    }

    @Test
    void testScalarMultiply() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            PublicKey g1 = PublicKey.fromInteger(smallInteger(rng));
            PublicKey g1Double = g1.add(g1);
            assertNotEquals(g1, g1Double);
            // scalar multiply by 2 is the same as adding oneself
            assertEquals(g1Double, g1.scalarMultiply(new byte[]{2}));
        }
    }

    @Test
    void testHashToG1DifferentDst() {
        byte[] defaultDst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_".getBytes(StandardCharsets.US_ASCII);
        byte[] customDst = "foobar".getBytes(StandardCharsets.US_ASCII);
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            byte[] msg = fill(rng, 32);
            PublicKey defaultHash = Bls.hashToG1(msg);
            assertEquals(defaultHash, Bls.hashToG1WithDst(msg, defaultDst));
            assertNotEquals(defaultHash, Bls.hashToG1WithDst(msg, customDst));
        }
    }

    // test cases from clvm_rs
    @Test
    void testHashToG1() {
        assertEquals("88e7302bf1fa8fcdecfb96f6b81475c3564d3bcaf552ccb338b1c48b9ba18ab7195c5067fe94fb216478188c0a3bef4a",
                hex(Bls.hashToG1("abcdef0123456789".getBytes(StandardCharsets.US_ASCII)).toBytes()));
    }

    // test cases from clvm_rs
    @ParameterizedTest
    @CsvSource({
            "abcdef0123456789, BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_, 8dd8e3a9197ddefdc25dde980d219004d6aa130d1af9b1808f8b2b004ae94484ac62a08a739ec7843388019a79c437b0",
            "abcdef0123456789, BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_, 88e7302bf1fa8fcdecfb96f6b81475c3564d3bcaf552ccb338b1c48b9ba18ab7195c5067fe94fb216478188c0a3bef4a",
    })
    void testHashToG1WithDst(String input, String dst, String expect) {
        PublicKey g1 = Bls.hashToG1WithDst(input.getBytes(StandardCharsets.US_ASCII), dst.getBytes(StandardCharsets.US_ASCII));
        assertEquals(expect, hex(g1.toBytes()));
    }
}
