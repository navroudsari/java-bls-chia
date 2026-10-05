package surf.superhighway.bls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * A BLS12-381 G2 element: a signature in the minimal-pubkey-size variant.
 *
 * <p>Instances are immutable and thread-safe. Serialized form is the 96-byte compressed
 * encoding used by Chia ({@code G2Element} in chia-bls).
 */
public final class Signature {

    public static final int SIZE = 96;

    private static final Signature INFINITY = new Signature(newPoint());
    private static final Signature GENERATOR = new Signature(copyOf(Blst.p2Generator()));

    // blst_p2 in a GC-managed off-heap arena; never written after construction.
    private final MemorySegment point;
    private final byte[] bytes;

    private Signature(MemorySegment point) {
        this.point = point;
        this.bytes = new byte[SIZE];
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(SIZE);
            Blst.p2Compress(out, point);
            MemorySegment.copy(out, JAVA_BYTE, 0, bytes, 0, SIZE);
        }
    }

    private Signature(MemorySegment point, byte[] canonicalBytes) {
        this.point = point;
        this.bytes = canonicalBytes;
    }

    static Signature fromPoint(MemorySegment point) {
        return new Signature(point);
    }

    static MemorySegment newPoint() {
        return Arena.ofAuto().allocate(Blst.P2_SIZE, Blst.ALIGNMENT);
    }

    private static MemorySegment copyOf(MemorySegment source) {
        MemorySegment copy = newPoint();
        MemorySegment.copy(source, 0, copy, 0, Blst.P2_SIZE);
        return copy;
    }

    /** The point at infinity (identity element); the aggregate of no signatures. */
    public static Signature infinity() {
        return INFINITY;
    }

    /** The G2 generator. */
    public static Signature generator() {
        return GENERATOR;
    }

    /**
     * Parses and validates a compressed signature: the encoding must be canonical and the point
     * must be the identity or lie in the G2 subgroup, as Chia's {@code G2Element::FromBytes} and
     * chia-bls {@code Signature::from_bytes} require.
     *
     * @throws BlsException if the bytes are not a valid signature
     */
    public static Signature fromBytes(byte[] bytes) {
        Signature signature = fromBytesUnchecked(bytes);
        if (!signature.isValid()) {
            // chia-bls reports a point outside G2 as BLST_POINT_NOT_ON_CURVE.
            throw BlsException.invalidSignature(BlstError.BLST_POINT_NOT_ON_CURVE);
        }
        return signature;
    }

    /**
     * Parses a compressed signature, checking the encoding and that the point is on the curve,
     * but <em>not</em> that it lies in the G2 subgroup. Verification methods in this library
     * reject signatures outside G2 regardless.
     *
     * @throws BlsException if the bytes are not a canonical encoding of a curve point
     */
    public static Signature fromBytesUnchecked(byte[] bytes) {
        Bytes.requireLength(bytes, SIZE, "signature");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment in = arena.allocateFrom(JAVA_BYTE, bytes);
            MemorySegment affine = arena.allocate(Blst.P2_AFFINE_SIZE, Blst.ALIGNMENT);
            int error = Blst.p2Uncompress(affine, in);
            if (error != Blst.BLST_SUCCESS) {
                throw BlsException.invalidSignature(BlstError.fromCode(error));
            }
            MemorySegment point = newPoint();
            Blst.p2FromAffine(point, affine);
            return new Signature(point, bytes.clone());
        }
    }

    /**
     * Parses the 192-byte uncompressed encoding (x || y). Like chia-bls
     * {@code Signature::from_uncompressed}, this checks the point is on the curve but not that it
     * lies in G2.
     *
     * @throws BlsException if the bytes are not an uncompressed curve point
     */
    public static Signature fromUncompressed(byte[] bytes) {
        Bytes.requireLength(bytes, 2 * SIZE, "uncompressed signature");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment affine = arena.allocate(Blst.P2_AFFINE_SIZE, Blst.ALIGNMENT);
            int error = Blst.p2Deserialize(affine, arena.allocateFrom(JAVA_BYTE, bytes));
            if (error != Blst.BLST_SUCCESS) {
                throw BlsException.invalidSignature(BlstError.fromCode(error));
            }
            MemorySegment point = newPoint();
            Blst.p2FromAffine(point, affine);
            return new Signature(point);
        }
    }

    /** Sums signatures. An empty list yields {@link #infinity()}. */
    public static Signature aggregate(List<Signature> signatures) {
        Objects.requireNonNull(signatures, "signatures");
        MemorySegment sum = newPoint();
        for (Signature signature : signatures) {
            Objects.requireNonNull(signature, "signatures contains null");
            Blst.p2AddOrDouble(sum, sum, signature.point);
        }
        return new Signature(sum);
    }

    /** The 96-byte compressed encoding. */
    public byte[] toBytes() {
        return bytes.clone();
    }

    /** True if this is the identity or lies in the G2 subgroup (Chia treats infinity as valid). */
    public boolean isValid() {
        return Blst.p2IsInf(point) || Blst.p2InG2(point);
    }

    public boolean isInfinity() {
        return Blst.p2IsInf(point);
    }

    public Signature add(Signature other) {
        Objects.requireNonNull(other, "other");
        MemorySegment sum = newPoint();
        Blst.p2AddOrDouble(sum, point, other.point);
        return new Signature(sum);
    }

    public Signature negate() {
        MemorySegment negated = copyOf(point);
        Blst.p2Cneg(negated, true);
        return new Signature(negated);
    }

    /**
     * Multiplies this point by an integer given as big-endian bytes of any length (reduced
     * modulo the group order), as chia-bls {@code Signature::scalar_multiply} does.
     */
    public Signature scalarMultiply(byte[] bigEndianInteger) {
        Objects.requireNonNull(bigEndianInteger, "bigEndianInteger");
        MemorySegment product = newPoint();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment scalar = arena.allocate(Blst.SCALAR_SIZE, Blst.ALIGNMENT);
            MemorySegment in = arena.allocate(Math.max(bigEndianInteger.length, 1));
            MemorySegment.copy(bigEndianInteger, 0, in, JAVA_BYTE, 0, bigEndianInteger.length);
            Blst.scalarFromBeBytes(scalar, in, bigEndianInteger.length);
            Blst.p2Mult(product, point, scalar, 256);
        }
        return new Signature(product);
    }

    /**
     * Unhardened child derivation of a G2 element, matching Chia's C++
     * {@code HDKeys::DeriveChildG2Unhardened} and Python {@code derive_child_g2_unhardened}:
     * {@code child = parent + G2 * int(SHA256(parent || index))} with the digest read big-endian.
     * (chia-bls in Rust has no G2 derivation.)
     *
     * @param index child index, interpreted as an unsigned 32-bit integer
     */
    public Signature deriveUnhardened(int index) {
        byte[] digest = Bytes.sha256(bytes, Bytes.uint32(index));
        MemorySegment child = newPoint();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment scalar = arena.allocate(Blst.SCALAR_SIZE, Blst.ALIGNMENT);
            Blst.scalarFromBeBytes(scalar, arena.allocateFrom(JAVA_BYTE, digest), digest.length);
            Blst.p2Mult(child, Blst.p2Generator(), scalar, 256);
            Blst.p2AddOrDouble(child, child, point);
        }
        return new Signature(child);
    }

    /**
     * The pairing {@code e(publicKey, this)}, with final exponentiation, as chia-bls
     * {@code Signature::pair}. No subgroup checks are made.
     */
    public GTElement pair(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        MemorySegment result = GTElement.newValue();
        try (Arena arena = Arena.ofConfined()) {
            Blst.millerLoop(result, toAffine(arena), publicKey.toAffine(arena));
            Blst.finalExp(result, result);
        }
        return GTElement.fromValue(result);
    }

    MemorySegment point() {
        return point;
    }

    MemorySegment toAffine(Arena arena) {
        MemorySegment affine = arena.allocate(Blst.P2_AFFINE_SIZE, Blst.ALIGNMENT);
        Blst.p2ToAffine(affine, point);
        return affine;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj instanceof Signature other && Blst.p2IsEqual(point, other.point);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    /** {@code <G2Element hex>}, as chia-bls's {@code Debug} output. */
    @Override
    public String toString() {
        return "<G2Element " + HexFormat.of().formatHex(bytes) + ">";
    }
}
