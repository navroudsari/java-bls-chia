package surf.superhighway.bls;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static surf.superhighway.bls.TestBytes.hex;

/** How Rust's unsigned and signed integers map onto this API. */
class IntegerTypesTest {

    private static final BigInteger R = Bls.GROUP_ORDER;

    // --- child indices: Rust u32, Java long checked to [0, 2^32) ---

    @ParameterizedTest
    @ValueSource(longs = {-1, -2147483648L, 4294967296L, Long.MAX_VALUE, Long.MIN_VALUE})
    void indicesOutsideU32AreRejectedEverywhere(long index) {
        PrivateKey sk = PrivateKey.fromSeed(TestBytes.repeat(1, 32));
        PublicKey pk = sk.getPublicKey();
        Signature sig = Bls.sign(sk, new byte[]{1});

        assertThrows(IllegalArgumentException.class, () -> sk.deriveHardened(index));
        assertThrows(IllegalArgumentException.class, () -> sk.deriveUnhardened(index));
        assertThrows(IllegalArgumentException.class, () -> pk.deriveUnhardened(index));
        assertThrows(IllegalArgumentException.class, () -> sig.deriveUnhardened(index));
        assertThrows(IllegalArgumentException.class, () -> HDKeys.masterToWalletUnhardened(pk, index));
        assertThrows(IllegalArgumentException.class, () -> HDKeys.deriveHardened(sk, 12381, index));
    }

    @ParameterizedTest
    @ValueSource(longs = {0, 1, 2147483647L, 2147483648L, 4294967295L})
    void indicesInsideU32AreAccepted(long index) {
        PrivateKey sk = PrivateKey.fromSeed(TestBytes.repeat(1, 32));
        assertDoesNotThrow(() -> sk.deriveHardened(index));
        assertEquals(sk.deriveUnhardened(index).getPublicKey(), sk.getPublicKey().deriveUnhardened(index));
    }

    @Test
    void intArgumentsStillWork() {
        PrivateKey sk = PrivateKey.fromSeed(TestBytes.repeat(1, 32));
        int index = 22;   // an int widens to long without a cast
        assertEquals(sk.deriveUnhardened(22L), sk.deriveUnhardened(index));
    }

    @Test
    void indexIsSerializedLikeRustU32ToBeBytes() {
        assertArrayEquals(new byte[]{0, 0, 0, 0}, Bytes.uint32(0));
        assertArrayEquals(new byte[]{0, 0, 0x30, 0x3d}, Bytes.uint32(12349));
        assertArrayEquals(new byte[]{(byte) 0x80, 0, 0, 0}, Bytes.uint32(2147483648L));
        assertArrayEquals(new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}, Bytes.uint32(4294967295L));
    }

    // --- fingerprint: Rust u32, Java long holding the unsigned value ---

    @Test
    void fingerprintIsTheUnsignedValue() {
        PublicKey pk = PrivateKey.fromSeed(new byte[32]).getPublicKey();
        long fingerprint = pk.getFingerprint();
        assertEquals(0xb40dd58aL, fingerprint);
        assertEquals("3020805514", Long.toString(fingerprint));
    }

    // --- scalars: byte[] is unsigned big-endian; BigInteger carries its own sign ---

    @Test
    void modGroupOrderIsAlwaysCanonical() {
        assertArrayEquals(new byte[32], Bls.modGroupOrder(BigInteger.ZERO));
        assertArrayEquals(new byte[32], Bls.modGroupOrder(R));
        assertArrayEquals(Bls.modGroupOrder(R.subtract(BigInteger.ONE)), Bls.modGroupOrder(BigInteger.ONE.negate()));
        assertEquals(32, Bls.modGroupOrder(BigInteger.TWO.pow(1000)).length);
        assertEquals(BigInteger.TWO.pow(1000).mod(R), new BigInteger(1, Bls.modGroupOrder(BigInteger.TWO.pow(1000))));
    }

    @Test
    void negativeScalarsNegateThePoint() {
        PublicKey g1 = PublicKey.generator();
        Signature g2 = Signature.generator();
        assertEquals(g1.negate(), PublicKey.fromInteger(BigInteger.ONE.negate()));
        assertEquals(g1.scalarMultiply(BigInteger.valueOf(7)).negate(), g1.scalarMultiply(BigInteger.valueOf(-7)));
        assertEquals(g2.scalarMultiply(BigInteger.valueOf(7)).negate(), g2.scalarMultiply(BigInteger.valueOf(-7)));
        assertEquals(PublicKey.infinity(), g1.scalarMultiply(R));
        assertEquals(g1, g1.scalarMultiply(R.add(BigInteger.ONE)));
    }

    @Test
    void sameBytesDifferentSignednessGiveDifferentResults() {
        byte[] atom = hex("deadbeef");   // top bit set: negative as two's complement
        PublicKey signed = PublicKey.fromInteger(new BigInteger(atom));
        PublicKey unsigned = PublicKey.fromInteger(new BigInteger(1, atom));
        assertEquals(unsigned, PublicKey.fromInteger(atom));   // byte[] overloads are unsigned
        assertEquals(PublicKey.fromInteger(new BigInteger(1, atom).subtract(BigInteger.TWO.pow(32))), signed);
    }

    /** clvm_rs op-tests: the operators read their scalar arguments as signed CLVM integers. */
    @TestFactory
    Stream<DynamicTest> clvmScalarOperatorVectors() throws IOException {
        String text;
        try (InputStream in = IntegerTypesTest.class.getResourceAsStream("/oracle/clvm_scalar_ops.txt")) {
            assertNotNull(in);
            text = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
        }
        return Arrays.stream(text.split("\\R"))
                .filter(line -> !line.isBlank() && !line.startsWith("#"))
                .map(line -> DynamicTest.dynamicTest(line.length() > 70 ? line.substring(0, 70) + "…" : line, () -> {
                    String[] tokens = line.split(" ");
                    String op = tokens[0];
                    boolean unary = op.equals("pubkey_for_exp");
                    BigInteger scalar = clvmInteger(tokens[unary ? 1 : 2]);
                    String expected = tokens[unary ? 3 : 4].substring(2);
                    switch (op) {
                        case "pubkey_for_exp" -> assertEquals(expected, hex(PublicKey.fromInteger(scalar).toBytes()));
                        case "g1_multiply" -> assertEquals(expected,
                                hex(PublicKey.fromBytes(hex(tokens[1])).scalarMultiply(scalar).toBytes()));
                        case "g2_multiply" -> assertEquals(expected,
                                hex(Signature.fromBytes(hex(tokens[1])).scalarMultiply(scalar).toBytes()));
                        default -> throw new AssertionError(op);
                    }
                }));
    }

    /** A CLVM integer literal: decimal, or a 0x atom as signed two's complement (empty atom is 0). */
    private static BigInteger clvmInteger(String token) {
        if (!token.startsWith("0x")) {
            return new BigInteger(token);
        }
        byte[] atom = hex(token);
        return atom.length == 0 ? BigInteger.ZERO : new BigInteger(atom);
    }
}
