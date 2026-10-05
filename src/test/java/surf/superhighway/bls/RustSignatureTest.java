package surf.superhighway.bls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.hex;
import static surf.superhighway.bls.TestBytes.of;

/**
 * Port of the tests in chia_rs {@code crates/chia-bls/src/signature.rs} (chia_rs 6485640).
 * Rust's seeded {@code StdRng} is replaced by {@code java.util.Random(1337)}. Rust's free
 * functions map to {@link Bls}; {@code agg += sig} and {@code agg.aggregate(sig)} map to
 * {@link Signature#add}.
 */
class RustSignatureTest {

    private static final String SK_HEX = "52d75c4707e39595b27314547f9723e5530c01198af3fc5849d9a7af65631efb";
    private static final byte[] FOOBAR = "foobar".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] FOO = "foo".getBytes(StandardCharsets.US_ASCII);

    private static byte[] fill(Random rng, int length) {
        byte[] out = new byte[length];
        rng.nextBytes(out);
        return out;
    }

    private static PrivateKey randomSk(Random rng) {
        return PrivateKey.fromSeed(fill(rng, 64));
    }

    private static Signature augMsgToG2(PublicKey pk, byte[] msg) {
        return Bls.hashToG2(Bytes.concat(pk.toBytes(), msg));
    }

    @Test
    void testFromBytes() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            byte[] data = fill(rng, 96);
            // just any random bytes are not a valid signature and should fail
            BlsException e = assertThrows(BlsException.class, () -> Signature.fromBytes(data));
            assertEquals(BlsException.Kind.INVALID_SIGNATURE, e.getKind());
            assertTrue(List.of(BlstError.BLST_BAD_ENCODING, BlstError.BLST_POINT_NOT_ON_CURVE).contains(e.getBlstError()),
                    e.getMessage());
        }
    }

    @Test
    void testDefaultIsValid() {
        assertTrue(Signature.infinity().isValid());
    }

    @Test
    void testInfinityIsValid() {
        byte[] data = new byte[96];
        data[0] = (byte) 0xc0;
        assertTrue(Signature.fromBytes(data).isValid());
    }

    @Test
    void testIsValid() {
        Random rng = new Random(1337);
        byte[] msg = new byte[32];
        for (int i = 0; i < 50; i++) {
            assertTrue(Bls.sign(PrivateKey.fromSeed(fill(rng, 32)), msg).isValid());
        }
    }

    @Test
    void testRoundtrip() {
        Random rng = new Random(1337);
        byte[] msg = fill(rng, 32);
        for (int i = 0; i < 50; i++) {
            Signature sig = Bls.sign(PrivateKey.fromSeed(fill(rng, 32)), msg);
            assertEquals(sig, Signature.fromBytes(sig.toBytes()));
        }
    }

    @Test
    void testRandomVerify() {
        Random rng = new Random(1337);
        byte[] msg = fill(rng, 32);
        for (int i = 0; i < 20; i++) {
            PrivateKey sk = PrivateKey.fromSeed(fill(rng, 32));
            PublicKey pk = sk.getPublicKey();
            Signature sig = Bls.sign(sk, msg);
            assertTrue(Bls.verify(sig, pk, msg));
            assertTrue(Bls.verify(Signature.fromBytes(sig.toBytes()), pk, msg));
        }
    }

    @Test
    void testVerify() {
        // blspy: AugSchemeMPL.sign(PrivateKey.from_bytes(SK_HEX), b"foobar")
        PrivateKey sk = PrivateKey.fromBytes(hex(SK_HEX));
        Signature sig = Bls.sign(sk, FOOBAR);
        assertTrue(Bls.verify(sig, sk.getPublicKey(), FOOBAR));
        assertEquals("b45825c0ee7759945c0189b4c38b7e54231ebadc83a851bec3bb7cf954a124ae0cc8e8e5146558332ea152f63bf8846e04826185ef60e817f271f8d500126561319203f9acb95809ed20c193757233454be1562a5870570941a84605bd2c9c9a",
                hex(sig.toBytes()));
    }

    @Test
    void testAggregateSignature() {
        // blspy: aggregate of AugSchemeMPL.sign(derive_child_sk(sk, i), b"foobar") for i in 0..4
        PrivateKey sk = PrivateKey.fromBytes(hex(SK_HEX));
        Signature agg1 = Signature.infinity();
        Signature agg2 = Signature.infinity();
        List<Signature> sigs = new ArrayList<>();
        List<PublicKey> pks = new ArrayList<>();
        List<byte[]> msgs = new ArrayList<>();
        List<PublicKey> pairG1 = new ArrayList<>();
        List<Signature> pairG2 = new ArrayList<>();
        for (int idx = 0; idx < 4; idx++) {
            PrivateKey derived = sk.deriveHardened(idx);
            PublicKey pk = derived.getPublicKey();
            pks.add(pk);
            msgs.add(FOOBAR);
            Signature sig = Bls.sign(derived, FOOBAR);
            agg1 = agg1.add(sig);
            agg2 = agg2.add(sig);
            sigs.add(sig);
            pairG1.add(pk);
            pairG2.add(augMsgToG2(pk, FOOBAR));
        }
        Signature agg3 = Bls.aggregate(sigs);
        Signature agg4 = sigs.get(0).add(sigs.get(1)).add(sigs.get(2)).add(sigs.get(3));

        assertEquals("87bce2c588f4257e2792d929834548c7d3af679272cb4f8e1d24cf4bf584dd287aa1d9f5e53a86f288190db45e1d100d0a5e936079a66a709b5f35394cf7d52f49dd963284cb5241055d54f8cf48f61bc1037d21cae6c025a7ea5e9f4d289a18",
                hex(agg1.toBytes()));
        assertEquals(agg1, agg2);
        assertEquals(agg1, agg3);
        assertEquals(agg1, agg4);

        // ensure the aggregate signature verifies OK
        assertTrue(Bls.aggregateVerify(agg1, pks, msgs));
        assertTrue(Bls.aggregateVerify(agg2, pks, msgs));
        assertTrue(Bls.aggregateVerify(agg3, pks, msgs));
        assertTrue(Bls.aggregateVerify(agg4, pks, msgs));

        pairG1.add(PublicKey.generator().negate());
        pairG2.add(agg1);
        assertTrue(Bls.aggregatePairing(pairG1, pairG2));
        // order does not matter
        Collections.reverse(pairG1);
        Collections.reverse(pairG2);
        assertTrue(Bls.aggregatePairing(pairG1, pairG2));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4, 5, 100})
    void testAggregateGtSignature(int numKeys) {
        PrivateKey sk = PrivateKey.fromBytes(hex(SK_HEX));
        Signature agg = Signature.infinity();
        List<GTElement> gts = new ArrayList<>();
        List<PublicKey> pks = new ArrayList<>();
        for (int idx = 0; idx < numKeys; idx++) {
            PrivateKey derived = sk.deriveHardened(idx);
            PublicKey pk = derived.getPublicKey();
            agg = agg.add(Bls.sign(derived, FOOBAR));
            gts.add(augMsgToG2(pk, FOOBAR).pair(pk));
            pks.add(pk);
        }

        assertTrue(Bls.aggregateVerifyGt(agg, gts));
        assertTrue(Bls.aggregateVerify(agg, pks, Collections.nCopies(pks.size(), FOOBAR)));

        // the order of the GTElements does not matter
        for (int i = 0; i < numKeys; i++) {
            Collections.rotate(gts, 1);
            Collections.rotate(pks, 1);
            assertTrue(Bls.aggregateVerifyGt(agg, gts));
            assertTrue(Bls.aggregateVerify(agg, pks, Collections.nCopies(pks.size(), FOOBAR)));
        }
        for (int i = 0; i < numKeys; i++) {
            Collections.rotate(gts, 1);
            Collections.rotate(pks, 1);
            assertFalse(Bls.aggregateVerifyGt(agg, gts.subList(1, gts.size())));
            assertFalse(Bls.aggregateVerify(agg, pks.subList(1, pks.size()), Collections.nCopies(pks.size() - 1, FOOBAR)));
        }
    }

    @Test
    void testAggregateDuplicateSignature() {
        PrivateKey sk = PrivateKey.fromBytes(hex(SK_HEX));
        PublicKey pk = sk.getPublicKey();
        Signature agg = Signature.infinity();
        List<PublicKey> pks = new ArrayList<>();
        List<byte[]> msgs = new ArrayList<>();
        List<PublicKey> pairG1 = new ArrayList<>();
        List<Signature> pairG2 = new ArrayList<>();
        for (int idx = 0; idx < 2; idx++) {
            pks.add(pk);
            msgs.add(FOOBAR);
            agg = agg.add(Bls.sign(sk, FOOBAR));
            pairG1.add(pk);
            pairG2.add(augMsgToG2(pk, FOOBAR));
        }

        assertEquals("a1cca6540a4a06d096cb5b5fc76af5fd099476e70b623b8c6e4cf02ffde94fc0f75f4e17c67a9e350940893306798a3519368b02dc3464b7270ea4ca233cfa85a38da9e25c9314e81270b54d1e773a2ec5c3e14c62dac7abdebe52f4688310d3",
                hex(agg.toBytes()));
        assertTrue(Bls.aggregateVerify(agg, pks, msgs));

        pairG1.add(PublicKey.generator().negate());
        pairG2.add(agg);
        assertTrue(Bls.aggregatePairing(pairG1, pairG2));
        Collections.reverse(pairG1);
        Collections.reverse(pairG2);
        assertTrue(Bls.aggregatePairing(pairG1, pairG2));
    }

    @Test
    void testAggregateSignatureSeparateMsg() {
        Random rng = new Random(1337);
        PrivateKey sk0 = randomSk(rng);
        PrivateKey sk1 = randomSk(rng);
        List<PublicKey> pks = List.of(sk0.getPublicKey(), sk1.getPublicKey());
        List<byte[]> msgs = List.of(FOO, FOOBAR);
        Signature agg = Signature.infinity().add(Bls.sign(sk0, FOO)).add(Bls.sign(sk1, FOOBAR));

        assertTrue(Bls.aggregateVerify(agg, pks, msgs));
        // order does not matter
        assertTrue(Bls.aggregateVerify(agg, List.of(pks.get(1), pks.get(0)), List.of(FOOBAR, FOO)));
    }

    @Test
    void testAggregateSignatureIdentity() {
        // when verifying 0 messages, an identity signature is considered valid
        assertTrue(Bls.aggregateVerify(Signature.infinity(), List.of(), List.of()));
        assertTrue(Bls.aggregatePairing(List.of(PublicKey.generator().negate()), List.of(Signature.infinity())));
    }

    @Test
    void testInvalidAggregateSignature() {
        Random rng = new Random(1337);
        PrivateKey sk0 = randomSk(rng);
        PrivateKey sk1 = randomSk(rng);
        PublicKey pk0 = sk0.getPublicKey();
        PublicKey pk1 = sk1.getPublicKey();
        Signature g2s0 = augMsgToG2(pk0, FOO);
        Signature g2s1 = augMsgToG2(pk1, FOOBAR);
        Signature agg = Signature.infinity().add(Bls.sign(sk0, FOO)).add(Bls.sign(sk1, FOOBAR));

        assertFalse(Bls.aggregateVerify(agg, List.of(pk0), List.of(FOO)));
        assertFalse(Bls.aggregateVerify(agg, List.of(pk1), List.of(FOOBAR)));
        // public keys mixed with the wrong message
        assertFalse(Bls.aggregateVerify(agg, List.of(pk0, pk1), List.of(FOOBAR, FOO)));
        assertFalse(Bls.aggregateVerify(agg, List.of(pk1, pk0), List.of(FOO, FOOBAR)));

        PublicKey negGenerator = PublicKey.generator().negate();
        assertFalse(Bls.aggregatePairing(List.of(pk0, negGenerator), List.of(g2s0, agg)));
        assertFalse(Bls.aggregatePairing(List.of(pk1, negGenerator), List.of(g2s1, agg)));
        // public keys mixed with the wrong message
        assertFalse(Bls.aggregatePairing(List.of(pk0, pk1, negGenerator), List.of(g2s1, g2s0, agg)));
        assertFalse(Bls.aggregatePairing(List.of(pk1, pk0, negGenerator), List.of(g2s0, g2s1, agg)));
    }

    @Test
    void testVector2AggregateOfAggregates() {
        // bls-signatures/src/test.cpp: "Chia test vector 2 (Augmented, aggregate of aggregates)"
        byte[] message1 = of(1, 2, 3, 40);
        byte[] message2 = of(5, 6, 70, 201);
        byte[] message3 = of(9, 10, 11, 12, 13);
        byte[] message4 = of(15, 63, 244, 92, 0, 1);

        PrivateKey sk1 = PrivateKey.fromSeed(TestBytes.repeat(2, 32));
        PrivateKey sk2 = PrivateKey.fromSeed(TestBytes.repeat(3, 32));
        PublicKey pk1 = sk1.getPublicKey();
        PublicKey pk2 = sk2.getPublicKey();

        Signature aggL = Bls.aggregate(List.of(Bls.sign(sk1, message1), Bls.sign(sk2, message2)));
        Signature aggR = Bls.aggregate(List.of(Bls.sign(sk2, message1), Bls.sign(sk1, message3), Bls.sign(sk1, message1)));
        Signature aggsig = Bls.aggregate(List.of(aggL, aggR, Bls.sign(sk1, message4)));

        assertTrue(Bls.aggregateVerify(aggsig, List.of(pk1, pk2, pk2, pk1, pk1, pk1),
                List.of(message1, message2, message1, message3, message1, message4)));
        assertEquals("a1d5360dcb418d33b29b90b912b4accde535cf0e52caf467a005dc632d9f7af44b6c4e9acd46eac218b28cdb07a3e3bc087df1cd1e3213aa4e11322a3ff3847bbba0b2fd19ddc25ca964871997b9bceeab37a4c2565876da19382ea32a962200",
                hex(aggsig.toBytes()));
    }

    @Test
    void testSignatureZeroKey() {
        // bls-signatures/src/test.cpp: "Should sign with the zero key"
        assertEquals(Signature.infinity(), Bls.sign(PrivateKey.fromBytes(new byte[32]), of(1, 2, 3)));
    }

    @Test
    void testAggregateManyG2ElementsDiffMessage() {
        // bls-signatures/src/test.cpp: "Should Aug aggregate many G2Elements, diff message"
        Random rng = new Random(1337);
        List<PublicKey> pks = new ArrayList<>();
        List<byte[]> msgs = new ArrayList<>();
        List<Signature> sigs = new ArrayList<>();
        for (int i = 0; i < 80; i++) {
            byte[] message = of(0, 100, 2, 45, 64, 12, 12, 63, i);
            PrivateKey sk = randomSk(rng);
            sigs.add(Bls.sign(sk, message));
            pks.add(sk.getPublicKey());
            msgs.add(message);
        }
        assertTrue(Bls.aggregateVerify(Bls.aggregate(sigs), pks, msgs));
    }

    @Test
    void testAggregateIdentity() {
        // bls-signatures/src/test.cpp: "Aggregate Verification of zero items with infinity should pass"
        Signature sig = Signature.infinity();
        Signature aggsig = Bls.aggregate(List.of(sig));
        assertEquals(sig, aggsig);
        assertEquals(Signature.infinity(), aggsig);
        assertTrue(Bls.aggregateVerify(aggsig, List.of(), List.of()));
    }

    @Test
    void testAggregateMultipleLevelsDegenerate() {
        // bls-signatures/src/test.cpp: "Should aggregate with multiple levels, degenerate"
        Random rng = new Random(1337);
        byte[] message1 = of(100, 2, 254, 88, 90, 45, 23);
        PrivateKey sk1 = randomSk(rng);
        Signature aggSig = Bls.sign(sk1, message1);
        List<PublicKey> pks = new ArrayList<>(List.of(sk1.getPublicKey()));
        List<byte[]> msgs = new ArrayList<>(List.of(message1));
        for (int i = 0; i < 10; i++) {
            PrivateKey sk = randomSk(rng);
            pks.add(sk.getPublicKey());
            msgs.add(message1);
            aggSig = aggSig.add(Bls.sign(sk, message1));
        }
        assertTrue(Bls.aggregateVerify(aggSig, pks, msgs));
    }

    @Test
    void testAggregateMultipleLevelsDifferentMessages() {
        // bls-signatures/src/test.cpp: "Should aggregate with multiple levels, different messages"
        Random rng = new Random(1337);
        byte[] message1 = of(100, 2, 254, 88, 90, 45, 23);
        byte[] message2 = of(192, 29, 2, 0, 0, 45, 23);
        byte[] message3 = of(52, 29, 2, 0, 0, 45, 102);
        byte[] message4 = of(99, 29, 2, 0, 0, 45, 222);
        PrivateKey sk1 = randomSk(rng);
        PrivateKey sk2 = randomSk(rng);
        PublicKey pk1 = sk1.getPublicKey();
        PublicKey pk2 = sk2.getPublicKey();

        Signature aggL = Bls.aggregate(List.of(Bls.sign(sk1, message1), Bls.sign(sk2, message2)));
        Signature aggR = Bls.aggregate(List.of(Bls.sign(sk2, message3), Bls.sign(sk1, message4)));
        Signature agg = Bls.aggregate(List.of(aggL, aggR));

        assertTrue(Bls.aggregateVerify(agg, List.of(pk1, pk2, pk2, pk1), List.of(message1, message2, message3, message4)));
    }

    @Test
    void testAugScheme() {
        // bls-signatures/src/test.cpp: "Aug Scheme"
        byte[] msg1 = of(7, 8, 9);
        byte[] msg2 = of(10, 11, 12);

        PrivateKey sk1 = PrivateKey.fromSeed(TestBytes.repeat(4, 32));
        PublicKey pk1 = sk1.getPublicKey();
        byte[] pk1v = pk1.toBytes();
        Signature sig1 = Bls.sign(sk1, msg1);
        byte[] sig1v = sig1.toBytes();
        assertTrue(Bls.verify(sig1, pk1, msg1));
        assertTrue(Bls.verify(Signature.fromBytes(sig1v), PublicKey.fromBytes(pk1v), msg1));

        PrivateKey sk2 = PrivateKey.fromSeed(TestBytes.repeat(5, 32));
        PublicKey pk2 = sk2.getPublicKey();
        byte[] pk2v = pk2.toBytes();
        Signature sig2 = Bls.sign(sk2, msg2);
        byte[] sig2v = sig2.toBytes();
        assertTrue(Bls.verify(sig2, pk2, msg2));
        assertTrue(Bls.verify(Signature.fromBytes(sig2v), PublicKey.fromBytes(pk2v), msg2));

        // Wrong G2Element
        assertFalse(Bls.verify(sig2, pk1, msg1));
        assertFalse(Bls.verify(Signature.fromBytes(sig2v), PublicKey.fromBytes(pk1v), msg1));
        // Wrong msg
        assertFalse(Bls.verify(sig1, pk1, msg2));
        assertFalse(Bls.verify(Signature.fromBytes(sig1v), PublicKey.fromBytes(pk1v), msg2));
        // Wrong pk
        assertFalse(Bls.verify(sig1, pk2, msg1));
        assertFalse(Bls.verify(Signature.fromBytes(sig1v), PublicKey.fromBytes(pk2v), msg1));

        Signature aggsig = Bls.aggregate(List.of(sig1, sig2));
        assertTrue(Bls.aggregateVerify(aggsig, List.of(pk1, pk2), List.of(msg1, msg2)));
        assertTrue(Bls.aggregateVerify(Signature.fromBytes(aggsig.toBytes()), List.of(pk1, pk2), List.of(msg1, msg2)));
    }

    @Test
    void testHash() {
        Random rng = new Random(1337);
        PrivateKey sk = PrivateKey.fromSeed(fill(rng, 32));
        Signature sig1 = Bls.sign(sk, of(0, 1, 2));
        Signature sig2 = Bls.sign(sk, of(0, 1, 2, 3));

        assertNotEquals(sig1.hashCode(), sig2.hashCode());
        assertEquals(Bls.sign(sk, of(0, 1, 2)).hashCode(), Bls.sign(sk, of(0, 1, 2)).hashCode());
    }

    @Test
    void testDebug() {
        byte[] data = new byte[96];
        data[0] = (byte) 0xc0;
        assertEquals("<G2Element " + hex(data) + ">", Signature.fromBytes(data).toString());
    }

    @Test
    void testGenerator() {
        assertEquals("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                hex(Signature.generator().toBytes()));
    }

    // test cases from zksnark test in chia_rs
    @ParameterizedTest
    @CsvSource({
            "0a7ecb9c6d6f0af8d922c9b348d686f7f827c5f5d7a53036e5dd6c4cfe088806375d730251df57c03b0eaa41ca2a9cc51817cfd6118c065e9b337e42a6b66621e2ffa79f576ae57dcb4916459b0131d42383b790a4f60c5aeb339b61a78d85a808b73e0701084dc16b5d7aa8c2f5385f83a217bc29934d0d02c51365410232e3c0288438e3110aa6e8cdef7bd32c46d60d0104952aaa0f0545cbe1548b70eed8b543ce19ede34cc51a387d092221417db0253f4651666b17303e225eac706107, 8a7ecb9c6d6f0af8d922c9b348d686f7f827c5f5d7a53036e5dd6c4cfe088806375d730251df57c03b0eaa41ca2a9cc51817cfd6118c065e9b337e42a6b66621e2ffa79f576ae57dcb4916459b0131d42383b790a4f60c5aeb339b61a78d85a8",
            "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801, 93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            "140acf170629d78244fb753f05fb79578add9217add53996d5de7c3005880c0dea903f851d6be749ebfb81c9721871370ef60428444d76f4ff81515628a4eb63e72c3cd7651a23c4eca109d1d88fec5a53626b36c76407926f308366b5ded1b219a481d87c6f87a4021fa8aa32851874f01b3eb011f6ed69c7884717fb0f5239bdc7310c2bc287659cd4a93976deaac20f4a21f0b004c767be4a21f36861616a5399b3e27431dc8133f325603230eaf1debdce8077105ab46baafa4836842305, b40acf170629d78244fb753f05fb79578add9217add53996d5de7c3005880c0dea903f851d6be749ebfb81c9721871370ef60428444d76f4ff81515628a4eb63e72c3cd7651a23c4eca109d1d88fec5a53626b36c76407926f308366b5ded1b2",
    })
    void testFromUncompressed(String input, String expect) {
        assertEquals(expect, hex(Signature.fromUncompressed(hex(input)).toBytes()));
    }

    @Test
    void testNegateRoundtrip() {
        Random rng = new Random(1337);
        byte[] msg = fill(rng, 32);
        for (int i = 0; i < 50; i++) {
            Signature g2 = Bls.sign(PrivateKey.fromSeed(fill(rng, 32)), msg);
            Signature g2Neg = g2.negate();
            assertNotEquals(g2, g2Neg);
            assertEquals(g2, g2Neg.negate());
        }
    }

    @Test
    void testNegateInfinity() {
        // negate on infinity is a no-op
        assertEquals(Signature.infinity(), Signature.infinity().negate());
    }

    @Test
    void testNegate() {
        Random rng = new Random(1337);
        byte[] msg = fill(rng, 32);
        for (int i = 0; i < 50; i++) {
            Signature g2 = Bls.sign(PrivateKey.fromSeed(fill(rng, 32)), msg);
            Signature g2Double = g2.add(g2);
            // adding the negative undoes adding the positive
            assertNotEquals(g2, g2Double);
            assertEquals(g2, g2Double.add(g2.negate()));
        }
    }

    @Test
    void testScalarMultiply() {
        Random rng = new Random(1337);
        byte[] msg = fill(rng, 32);
        for (int i = 0; i < 50; i++) {
            Signature g2 = Bls.sign(PrivateKey.fromSeed(fill(rng, 32)), msg);
            Signature g2Double = g2.add(g2);
            assertNotEquals(g2, g2Double);
            // scalar multiply by 2 is the same as adding oneself
            assertEquals(g2Double, g2.scalarMultiply(new byte[]{2}));
        }
    }

    @Test
    void testHashToG2DifferentDst() {
        byte[] defaultDst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_".getBytes(StandardCharsets.US_ASCII);
        byte[] customDst = "foobar".getBytes(StandardCharsets.US_ASCII);
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            byte[] msg = fill(rng, 32);
            Signature defaultHash = Bls.hashToG2(msg);
            assertEquals(defaultHash, Bls.hashToG2WithDst(msg, defaultDst));
            assertNotEquals(defaultHash, Bls.hashToG2WithDst(msg, customDst));
        }
    }

    // test cases from clvm_rs
    @Test
    void testHashToG2() {
        assertEquals("92596412844e12c4733b5a6bfc5727cde4c20b345665d2de99de163266f3ba6a944c6c0fdd9d9fe57b9a4acb769bf3780456f8aab4cd41a70836dba57a5278a85fbd18eb96a2b56cfbda853186c9d190c43e63bc3e6a181aed692e97bbdb1944",
                hex(Bls.hashToG2("abcdef0123456789".getBytes(StandardCharsets.US_ASCII)).toBytes()));
    }

    // test cases from clvm_rs
    @ParameterizedTest
    @CsvSource({
            "abcdef0123456789, BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_, 8ee1ff66094b8975401c86ad424076d97fed9c2025db5f9dfde6ed455c7bff34b55e96379c1f9ee3c173633587f425e50aed3e807c6c7cd7bed35d40542eee99891955b2ea5321ebde37172e2c01155138494c2d725b03c02765828679bf011e",
            "abcdef0123456789, BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_, 92596412844e12c4733b5a6bfc5727cde4c20b345665d2de99de163266f3ba6a944c6c0fdd9d9fe57b9a4acb769bf3780456f8aab4cd41a70836dba57a5278a85fbd18eb96a2b56cfbda853186c9d190c43e63bc3e6a181aed692e97bbdb1944",
    })
    void testHashToG2WithDst(String input, String dst, String expect) {
        Signature g2 = Bls.hashToG2WithDst(input.getBytes(StandardCharsets.US_ASCII), dst.getBytes(StandardCharsets.US_ASCII));
        assertEquals(expect, hex(g2.toBytes()));
    }
}
