package surf.superhighway.bls;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
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

/** Regression tests for the issues found in the code review of the jblst-based implementation. */
class ReviewRegressionTest {

    private static final BigInteger R = new BigInteger("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001", 16);
    private static final byte[] NOT_IN_G1 = hex("8d5d0fb73b9c92df4eab4216e48c3e358578b4cc30f82c268bd6fef3bd34b558628daf1afef798d4c3b0fcd8b28c8973");

    private final BasicSignatureScheme basic = BasicSignatureScheme.getInstance();

    /** A non-zero point of the G1 cofactor torsion: r * B for B on the curve but outside G1. */
    private static PublicKey torsionPoint() {
        PublicKey b = PublicKey.fromBytesUnchecked(NOT_IN_G1);
        byte[] rMinusOne = R.subtract(BigInteger.ONE).toByteArray();
        PublicKey torsion = b.scalarMultiply(rMinusOne).add(b);
        assertFalse(torsion.isInfinity());
        assertFalse(torsion.isValid());
        return torsion;
    }

    private static byte[] onCurveNotInG2() {
        for (int i = 0; i < 1000; i++) {
            byte[] encoding = random(96);
            encoding[0] = (byte) (0x80 | (encoding[0] & 0x0f));
            encoding[48] = (byte) (encoding[48] & 0x0f);
            try {
                Signature candidate = Signature.fromBytesUnchecked(encoding);
                if (!candidate.isValid()) {
                    return encoding;
                }
            } catch (IllegalArgumentException notOnCurve) {
                // try another
            }
        }
        throw new IllegalStateException("no on-curve point found");
    }

    @Test
    void hardenedDerivationReturnsTheChildAndLeavesParentUnchanged() {
        PrivateKey parent = PrivateKey.fromSeed(repeat(7, 32));
        byte[] before = parent.toBytes();

        PrivateKey child = parent.deriveHardened(3);

        assertNotEquals(parent, child);
        assertArrayEquals(before, parent.toBytes());
        // Chia uses KeyGen v3 after the Lamport step; blst's derive_child_eip2333 (KeyGen v4) gives 10ab36...
        assertNotEquals("10ab369cb4b4072e084061b55e4ebb26451c6797eeaac97c3bfb7b0beca869ed", hex(child.toBytes()));
        assertEquals("4bbf199197b460520ee040bbea24aa1cfd437ab8679b06ed32f0ac3287fb291a", hex(child.toBytes()));
    }

    @Test
    void unhardenedDerivationDoesNotMutateInputs() {
        PublicKey parentPk = PrivateKey.fromSeed(repeat(7, 32)).getPublicKey();
        byte[] pkBefore = parentPk.toBytes();
        parentPk.deriveUnhardened(1);
        assertArrayEquals(pkBefore, parentPk.toBytes());
        assertEquals(PublicKey.fromBytes(pkBefore), parentPk);

        Signature signature = basic.sign(PrivateKey.fromSeed(repeat(7, 32)), of(1, 2, 3));
        byte[] sigBefore = signature.toBytes();
        signature.deriveUnhardened(1);
        assertArrayEquals(sigBefore, signature.toBytes());
        assertEquals(Signature.fromBytes(sigBefore), signature);
    }

    @Test
    void derivingFromInfinityDoesNotCorruptSharedInstances() {
        Signature.infinity().deriveUnhardened(0);
        PublicKey.infinity().deriveUnhardened(0);

        assertTrue(Signature.infinity().isInfinity());
        assertTrue(PublicKey.infinity().isInfinity());
        assertTrue(basic.aggregateVerify(List.of(), List.of(), Signature.fromBytes(Signature.infinity().toBytes())));
    }

    @Test
    void aggregateVerifyRejectsPublicKeyOutsideG1() {
        PrivateKey sk = PrivateKey.fromSeed(repeat(7, 32));
        byte[] message = of(9, 9, 9);
        Signature signature = basic.sign(sk, message);

        PublicKey tampered = PublicKey.fromBytesUnchecked(sk.getPublicKey().add(torsionPoint()).toBytes());
        assertFalse(tampered.isValid());

        assertFalse(basic.verify(tampered, message, signature));
        assertFalse(basic.aggregateVerify(List.of(tampered), List.of(message), signature));
        assertTrue(basic.aggregateVerify(List.of(sk.getPublicKey()), List.of(message), signature));
    }

    @Test
    void fastAggregateVerifyRejectsTorsionThatCancelsInTheSum() {
        ProofOfPossessionSignatureScheme pop = ProofOfPossessionSignatureScheme.getInstance();
        PrivateKey sk1 = PrivateKey.fromSeed(repeat(1, 32));
        PrivateKey sk2 = PrivateKey.fromSeed(repeat(2, 32));
        byte[] message = of(4, 5, 6);
        Signature aggregate = pop.aggregateSignatures(List.of(pop.sign(sk1, message), pop.sign(sk2, message)));

        PublicKey torsion = torsionPoint();
        PublicKey pk1 = sk1.getPublicKey().add(torsion);
        PublicKey pk2 = sk2.getPublicKey().add(torsion.negate());
        assertTrue(PublicKey.aggregate(List.of(pk1, pk2)).isValid(), "sum is back in G1");

        assertFalse(pop.fastAggregateVerify(List.of(pk1, pk2), message, aggregate));
        assertTrue(pop.fastAggregateVerify(List.of(sk1.getPublicKey(), sk2.getPublicKey()), message, aggregate));
    }

    @Test
    void signatureFromBytesRejectsPointsOutsideG2() {
        byte[] encoding = onCurveNotInG2();
        assertThrows(IllegalArgumentException.class, () -> Signature.fromBytes(encoding));

        Signature unchecked = Signature.fromBytesUnchecked(encoding);
        PublicKey pk = PrivateKey.fromSeed(repeat(3, 32)).getPublicKey();
        assertFalse(basic.verify(pk, of(1), unchecked));
        assertFalse(basic.aggregateVerify(List.of(pk), List.of(of(1)), unchecked));
    }

    @Test
    void privateKeyEqualToGroupOrderIsRejected() {
        byte[] r = new byte[32];
        byte[] rBytes = R.toByteArray();
        System.arraycopy(rBytes, rBytes.length - 32, r, 0, 32);
        assertThrows(IllegalArgumentException.class, () -> PrivateKey.fromBytes(r));
        assertTrue(PrivateKey.fromBytesModOrder(r).getPublicKey().isInfinity());
    }

    @Test
    void privateKeyToStringDoesNotRevealKeyMaterial() {
        PrivateKey sk = PrivateKey.fromSeed(repeat(7, 32));
        assertEquals("<PrivateKey>", sk.toString());
        assertFalse(String.valueOf(sk).contains(hex(sk.toBytes())));
    }

    @Test
    void equalsHandlesNullAndOtherTypes() {
        PublicKey pk = PrivateKey.fromSeed(repeat(7, 32)).getPublicKey();
        assertFalse(pk.equals(null));
        assertFalse(pk.equals("pk"));
        assertFalse(Signature.infinity().equals(null));
        assertFalse(PrivateKey.fromSeed(repeat(7, 32)).equals(null));
    }

    @Test
    void nonCanonicalEncodingsAreRejected() {
        byte[] infinityWithJunk = new byte[48];
        infinityWithJunk[0] = (byte) 0xc0;
        infinityWithJunk[47] = 1;
        assertThrows(IllegalArgumentException.class, () -> PublicKey.fromBytesUnchecked(infinityWithJunk));

        byte[] infinityWithSignBit = new byte[48];
        infinityWithSignBit[0] = (byte) 0xe0;
        assertThrows(IllegalArgumentException.class, () -> PublicKey.fromBytesUnchecked(infinityWithSignBit));

        byte[] uncompressedFlag = PrivateKey.fromSeed(repeat(7, 32)).getPublicKey().toBytes();
        uncompressedFlag[0] &= 0x7f;
        assertThrows(IllegalArgumentException.class, () -> PublicKey.fromBytesUnchecked(uncompressedFlag));

        byte[] zeroX = new byte[48];
        zeroX[0] = (byte) 0x80;
        assertThrows(IllegalArgumentException.class, () -> PublicKey.fromBytesUnchecked(zeroX));

        byte[] g2InfinityWithJunk = new byte[96];
        g2InfinityWithJunk[0] = (byte) 0xc0;
        g2InfinityWithJunk[95] = 1;
        assertThrows(IllegalArgumentException.class, () -> Signature.fromBytesUnchecked(g2InfinityWithJunk));
    }

    @Test
    void infinityPublicKeyNeverVerifies() {
        Signature infinity = Signature.infinity();
        assertFalse(basic.verify(PublicKey.infinity(), of(1), infinity));
        assertFalse(basic.aggregateVerify(List.of(PublicKey.infinity()), List.of(of(1)), infinity));
    }
}
