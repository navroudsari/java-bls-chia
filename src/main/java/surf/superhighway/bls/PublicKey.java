package surf.superhighway.bls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * A BLS12-381 G1 element: a public key in the minimal-pubkey-size variant.
 *
 * <p>Instances are immutable and thread-safe. Serialized form is the 48-byte compressed
 * encoding used by Chia ({@code G1Element} in chia-bls).
 */
public final class PublicKey {

    public static final int SIZE = 48;

    private static final PublicKey INFINITY = new PublicKey(newPoint());
    private static final PublicKey GENERATOR = new PublicKey(copyOf(Blst.p1Generator()));

    // blst_p1 in a GC-managed off-heap arena; never written after construction.
    private final MemorySegment point;
    private final byte[] bytes;

    private PublicKey(MemorySegment point) {
        this.point = point;
        this.bytes = new byte[SIZE];
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(SIZE);
            Blst.p1Compress(out, point);
            MemorySegment.copy(out, JAVA_BYTE, 0, bytes, 0, SIZE);
        }
    }

    private PublicKey(MemorySegment point, byte[] canonicalBytes) {
        this.point = point;
        this.bytes = canonicalBytes;
    }

    static PublicKey fromPoint(MemorySegment point) {
        return new PublicKey(point);
    }

    static MemorySegment newPoint() {
        return Arena.ofAuto().allocate(Blst.P1_SIZE, Blst.ALIGNMENT);
    }

    private static MemorySegment copyOf(MemorySegment source) {
        MemorySegment copy = newPoint();
        MemorySegment.copy(source, 0, copy, 0, Blst.P1_SIZE);
        return copy;
    }

    /** The point at infinity (identity element). */
    public static PublicKey infinity() {
        return INFINITY;
    }

    /** The G1 generator. */
    public static PublicKey generator() {
        return GENERATOR;
    }

    /**
     * Parses and validates a compressed public key: the encoding must be canonical and the point
     * must be the identity or lie in the G1 subgroup.
     *
     * @throws BlsException if the bytes are not a valid public key
     */
    public static PublicKey fromBytes(byte[] bytes) {
        PublicKey publicKey = fromBytesUnchecked(bytes);
        if (!publicKey.isValid()) {
            // chia-bls reports a point outside G1 as BLST_POINT_NOT_ON_CURVE.
            throw BlsException.invalidPublicKey(BlstError.BLST_POINT_NOT_ON_CURVE);
        }
        return publicKey;
    }

    /**
     * Parses a compressed public key, checking the encoding is canonical and the point is on the
     * curve, but <em>not</em> that it lies in the G1 subgroup. Only use this for keys from a
     * trusted source; {@link #isValid()} performs the remaining check. Verification methods in
     * this library reject keys outside G1 regardless.
     *
     * @throws BlsException if the bytes are not a canonical encoding of a curve point
     */
    public static PublicKey fromBytesUnchecked(byte[] bytes) {
        Bytes.requireLength(bytes, SIZE, "public key");

        // Canonical-encoding checks mirror chia-bls PublicKey::from_bytes_unchecked.
        int first = bytes[0] & 0xff;
        boolean zerosOnly = Bytes.allZero(bytes, 1);
        if ((first & 0xc0) == 0xc0) {
            if (first != 0xc0 || !zerosOnly) {
                throw BlsException.of(BlsException.Kind.G1_NOT_CANONICAL);
            }
            return INFINITY;
        }
        if ((first & 0xc0) != 0x80) {
            throw BlsException.of(BlsException.Kind.G1_INFINITY_INVALID_BITS);
        }
        if (zerosOnly) {
            throw BlsException.of(BlsException.Kind.G1_INFINITY_NOT_ZERO);
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment in = arena.allocateFrom(JAVA_BYTE, bytes);
            MemorySegment affine = arena.allocate(Blst.P1_AFFINE_SIZE, Blst.ALIGNMENT);
            int error = Blst.p1Uncompress(affine, in);
            if (error != Blst.BLST_SUCCESS) {
                throw BlsException.invalidPublicKey(BlstError.fromCode(error));
            }
            MemorySegment point = newPoint();
            Blst.p1FromAffine(point, affine);
            return new PublicKey(point, bytes.clone());
        }
    }

    /**
     * Parses the 96-byte uncompressed encoding (x || y). Like chia-bls
     * {@code PublicKey::from_uncompressed}, this checks the point is on the curve but not that it
     * lies in G1.
     *
     * @throws BlsException if the bytes are not an uncompressed curve point
     */
    public static PublicKey fromUncompressed(byte[] bytes) {
        Bytes.requireLength(bytes, 2 * SIZE, "uncompressed public key");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment affine = arena.allocate(Blst.P1_AFFINE_SIZE, Blst.ALIGNMENT);
            int error = Blst.p1Deserialize(affine, arena.allocateFrom(JAVA_BYTE, bytes));
            if (error != Blst.BLST_SUCCESS) {
                throw BlsException.invalidPublicKey(BlstError.fromCode(error));
            }
            MemorySegment point = newPoint();
            Blst.p1FromAffine(point, affine);
            return new PublicKey(point);
        }
    }

    /**
     * {@code G1 * n} for an integer given as unsigned big-endian bytes (reduced modulo the group order):
     * the public key of the private key {@code n}. chia-bls {@code PublicKey::from_integer}.
     */
    public static PublicKey fromInteger(byte[] bigEndianInteger) {
        return GENERATOR.scalarMultiply(bigEndianInteger);
    }

    /**
     * {@code G1 * n} for an integer of any sign, reduced modulo the group order (so
     * {@code fromInteger(-1)} is {@code generator().negate()}). This is clvm's
     * {@code pubkey_for_exp}.
     */
    public static PublicKey fromInteger(BigInteger n) {
        return GENERATOR.scalarMultiply(n);
    }

    /** Sums public keys. An empty list yields {@link #infinity()}. */
    public static PublicKey aggregate(List<PublicKey> publicKeys) {
        Objects.requireNonNull(publicKeys, "publicKeys");
        MemorySegment sum = newPoint();
        for (PublicKey publicKey : publicKeys) {
            Objects.requireNonNull(publicKey, "publicKeys contains null");
            Blst.p1AddOrDouble(sum, sum, publicKey.point);
        }
        return new PublicKey(sum);
    }

    /** The 48-byte compressed encoding. */
    public byte[] toBytes() {
        return bytes.clone();
    }

    /** True if this is the identity or lies in the G1 subgroup (Chia treats infinity as valid). */
    public boolean isValid() {
        return Blst.p1IsInf(point) || Blst.p1InG1(point);
    }

    public boolean isInfinity() {
        return Blst.p1IsInf(point);
    }

    public PublicKey add(PublicKey other) {
        Objects.requireNonNull(other, "other");
        MemorySegment sum = newPoint();
        Blst.p1AddOrDouble(sum, point, other.point);
        return new PublicKey(sum);
    }

    public PublicKey negate() {
        MemorySegment negated = copyOf(point);
        Blst.p1Cneg(negated, true);
        return new PublicKey(negated);
    }

    /**
     * Multiplies this point by an integer given as unsigned big-endian bytes of any length (reduced
     * modulo the group order), as chia-bls {@code PublicKey::scalar_multiply} does.
     */
    public PublicKey scalarMultiply(byte[] bigEndianInteger) {
        Objects.requireNonNull(bigEndianInteger, "bigEndianInteger");
        MemorySegment product = newPoint();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment scalar = arena.allocate(Blst.SCALAR_SIZE, Blst.ALIGNMENT);
            MemorySegment in = arena.allocate(Math.max(bigEndianInteger.length, 1));
            MemorySegment.copy(bigEndianInteger, 0, in, JAVA_BYTE, 0, bigEndianInteger.length);
            Blst.scalarFromBeBytes(scalar, in, bigEndianInteger.length);
            Blst.p1Mult(product, point, scalar, 256);
        }
        return new PublicKey(product);
    }

    /**
     * Multiplies this point by an integer of any sign, reduced modulo the group order, as clvm's
     * {@code g1_multiply} does.
     */
    public PublicKey scalarMultiply(BigInteger n) {
        return scalarMultiply(Bls.modGroupOrder(n));
    }

    /** First four bytes of SHA-256 of the serialized key, as an unsigned 32-bit value. */
    public long getFingerprint() {
        byte[] hash = Bytes.sha256(bytes);
        return ((hash[0] & 0xffL) << 24) | ((hash[1] & 0xffL) << 16) | ((hash[2] & 0xffL) << 8) | (hash[3] & 0xffL);
    }

    /**
     * Unhardened (BIP32-style) child derivation, matching chia-bls
     * {@code PublicKey::derive_unhardened}: {@code child = parent + G1 * int(SHA256(parent || index))}.
     *
     * @param index child index, 0 to 4294967295 (a Rust {@code u32})
     * @throws IllegalArgumentException if {@code index} is outside that range
     */
    public PublicKey deriveUnhardened(long index) {
        byte[] digest = Bytes.sha256(bytes, Bytes.uint32(index));
        MemorySegment child = newPoint();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment scalar = arena.allocate(Blst.SCALAR_SIZE, Blst.ALIGNMENT);
            Blst.scalarFromBeBytes(scalar, arena.allocateFrom(JAVA_BYTE, digest), digest.length);
            Blst.p1Mult(child, Blst.p1Generator(), scalar, 256);
            Blst.p1AddOrDouble(child, child, point);
        }
        return new PublicKey(child);
    }

    MemorySegment point() {
        return point;
    }

    MemorySegment toAffine(Arena arena) {
        MemorySegment affine = arena.allocate(Blst.P1_AFFINE_SIZE, Blst.ALIGNMENT);
        Blst.p1ToAffine(affine, point);
        return affine;
    }

    byte[] bytesUnsafe() {
        return bytes;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj instanceof PublicKey other && Blst.p1IsEqual(point, other.point);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    /** {@code <G1Element hex>}, as chia-bls's {@code Debug} output. */
    @Override
    public String toString() {
        return "<G1Element " + HexFormat.of().formatHex(bytes) + ">";
    }
}
