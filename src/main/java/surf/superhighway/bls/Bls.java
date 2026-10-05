package surf.superhighway.bls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * The free functions at the root of chia-bls ({@code chia_bls::sign}, {@code verify},
 * {@code aggregate_verify}, {@code hash_to_g1}, ...), with the same semantics and argument order.
 * Signing and verification use the augmentation scheme, as Chia does throughout.
 */
public final class Bls {

    private static final MessageAugmentationSignatureScheme AUG = MessageAugmentationSignatureScheme.getInstance();
    private static final byte[] G1_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_".getBytes(StandardCharsets.US_ASCII);

    /** The order r of G1, G2 and GT: scalars and private keys are integers modulo r. */
    public static final BigInteger GROUP_ORDER =
            new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private Bls() {
    }

    /**
     * {@code value mod r} as 32 big-endian bytes, for a value of any sign: negative values wrap
     * to {@code r - |value| mod r}. This is clvm's {@code mod_group_order} and chia-puzzle-types'
     * {@code mod_by_group_order}. Pass a {@code BigInteger} built with the signedness you mean:
     * {@code new BigInteger(bytes)} for two's-complement (CLVM atoms, Chia's synthetic-key
     * offset), {@code new BigInteger(1, bytes)} for unsigned.
     */
    public static byte[] modGroupOrder(BigInteger value) {
        Objects.requireNonNull(value, "value");
        byte[] magnitude = value.mod(GROUP_ORDER).toByteArray();   // non-negative, at most 33 bytes
        byte[] out = new byte[32];
        int length = Math.min(magnitude.length, 32);
        System.arraycopy(magnitude, magnitude.length - length, out, 32 - length, length);
        return out;
    }

    /** Signs {@code message} prefixed with the signer's public key. chia-bls {@code sign}. */
    public static Signature sign(PrivateKey privateKey, byte[] message) {
        return AUG.sign(privateKey, message);
    }

    /**
     * Signs {@code message} as-is under the augmentation scheme's tag, for callers that have
     * already prefixed it with some public key. chia-bls {@code sign_raw}.
     */
    public static Signature signRaw(PrivateKey privateKey, byte[] message) {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(message, "message");
        return privateKey.sign(message, AUG.dst());
    }

    /** chia-bls {@code verify(sig, key, msg)}. */
    public static boolean verify(Signature signature, PublicKey publicKey, byte[] message) {
        return AUG.verify(publicKey, message, signature);
    }

    /** chia-bls {@code aggregate}; an empty list yields the identity. */
    public static Signature aggregate(List<Signature> signatures) {
        return Signature.aggregate(signatures);
    }

    /**
     * chia-bls {@code aggregate_verify(sig, [(pk, msg), ...])}: rejects invalid points, and with
     * no pairs accepts only the identity signature.
     *
     * @throws IllegalArgumentException if the lists differ in size
     */
    public static boolean aggregateVerify(Signature signature, List<PublicKey> publicKeys, List<byte[]> messages) {
        return AUG.aggregateVerify(publicKeys, messages, signature);
    }

    /**
     * chia-bls {@code aggregate_verify_gt}: verifies {@code signature} against pairings already
     * computed as {@code hashToG2(pk || msg).pair(pk)}. With no pairings, accepts only the identity.
     */
    public static boolean aggregateVerifyGt(Signature signature, List<GTElement> pairings) {
        Objects.requireNonNull(signature, "signature");
        Objects.requireNonNull(pairings, "pairings");
        if (!signature.isValid()) {
            return false;
        }
        if (pairings.isEmpty()) {
            return signature.isInfinity();
        }
        GTElement product = Objects.requireNonNull(pairings.get(0), "pairings contains null");
        for (int i = 1; i < pairings.size(); i++) {
            product = product.multiply(Objects.requireNonNull(pairings.get(i), "pairings contains null"));
        }
        return product.equals(signature.pair(PublicKey.generator()));
    }

    /**
     * chia-bls {@code aggregate_pairing}: true if the product of {@code e(g1s[i], g2s[i])} is the
     * identity. All points must be valid. To check an aggregate signature, include the pair
     * {@code (-G1 generator, signature)}. With no pairs, returns true.
     *
     * @throws IllegalArgumentException if the lists differ in size
     */
    public static boolean aggregatePairing(List<PublicKey> g1s, List<Signature> g2s) {
        Objects.requireNonNull(g1s, "g1s");
        Objects.requireNonNull(g2s, "g2s");
        if (g1s.size() != g2s.size()) {
            throw new IllegalArgumentException("g1s and g2s must have the same size");
        }
        if (g1s.isEmpty()) {
            return true;
        }
        try (Arena arena = Arena.ofConfined()) {
            byte[] dst = AUG.dst();
            MemorySegment tag = arena.allocateFrom(JAVA_BYTE, dst);   // must outlive the context
            MemorySegment context = arena.allocate(Blst.PAIRING_SIZE, Blst.ALIGNMENT);
            Blst.pairingInit(context, tag, dst.length);
            for (int i = 0; i < g1s.size(); i++) {
                PublicKey g1 = Objects.requireNonNull(g1s.get(i), "g1s contains null");
                Signature g2 = Objects.requireNonNull(g2s.get(i), "g2s contains null");
                if (!g1.isValid() || !g2.isValid()) {
                    return false;
                }
                Blst.pairingRawAggregate(context, g2.toAffine(arena), g1.toAffine(arena));
            }
            Blst.pairingCommit(context);
            return Blst.pairingFinalVerify(context, MemorySegment.NULL);
        }
    }

    /** Hash to G1 with the augmentation scheme's G1 tag. chia-bls {@code hash_to_g1}. */
    public static PublicKey hashToG1(byte[] message) {
        return hashToG1WithDst(message, G1_DST);
    }

    /** chia-bls {@code hash_to_g1_with_dst}. */
    public static PublicKey hashToG1WithDst(byte[] message, byte[] dst) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(dst, "dst");
        MemorySegment point = PublicKey.newPoint();
        try (Arena arena = Arena.ofConfined()) {
            Blst.hashToG1(point, nativeBytes(arena, message), message.length, nativeBytes(arena, dst), dst.length);
        }
        return PublicKey.fromPoint(point);
    }

    /** Hash to G2 with the augmentation scheme's tag. chia-bls {@code hash_to_g2}. */
    public static Signature hashToG2(byte[] message) {
        return hashToG2WithDst(message, AUG.dst());
    }

    /** chia-bls {@code hash_to_g2_with_dst}. */
    public static Signature hashToG2WithDst(byte[] message, byte[] dst) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(dst, "dst");
        MemorySegment point = Signature.newPoint();
        try (Arena arena = Arena.ofConfined()) {
            Blst.hashToG2(point, nativeBytes(arena, message), message.length, nativeBytes(arena, dst), dst.length);
        }
        return Signature.fromPoint(point);
    }

    private static MemorySegment nativeBytes(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1));
        MemorySegment.copy(bytes, 0, segment, JAVA_BYTE, 0, bytes.length);
        return segment;
    }
}
