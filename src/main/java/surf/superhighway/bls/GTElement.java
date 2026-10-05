package surf.superhighway.bls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * An element of the pairing target group GT (a {@code blst_fp12}), as chia-bls {@code GTElement}.
 *
 * <p>Produced by {@link Signature#pair(PublicKey)} and consumed by
 * {@link Bls#aggregateVerifyGt} and {@link BlsCache}. The {@value #SIZE}-byte serialization is
 * blst's in-memory representation, exactly as chia-bls streams it (little-endian 64-bit limbs in
 * Montgomery form), so it is interchangeable with Chia's. Instances are immutable.
 */
public final class GTElement {

    public static final int SIZE = (int) Blst.FP12_SIZE;

    // blst_fp12 in a GC-managed off-heap arena; never written after construction.
    private final MemorySegment value;

    private GTElement(MemorySegment value) {
        this.value = value;
    }

    static MemorySegment newValue() {
        return Arena.ofAuto().allocate(Blst.FP12_SIZE, Blst.ALIGNMENT);
    }

    static GTElement fromValue(MemorySegment value) {
        return new GTElement(value);
    }

    /** Reads the raw {@value #SIZE}-byte representation. Like chia-bls, no validation is done. */
    public static GTElement fromBytes(byte[] bytes) {
        Bytes.requireLength(bytes, SIZE, "GTElement");
        MemorySegment value = newValue();
        MemorySegment.copy(bytes, 0, value, JAVA_BYTE, 0, SIZE);
        return new GTElement(value);
    }

    public byte[] toBytes() {
        byte[] out = new byte[SIZE];
        MemorySegment.copy(value, JAVA_BYTE, 0, out, 0, SIZE);
        return out;
    }

    /** The group operation (Fp12 multiplication), as chia-bls {@code GTElement * GTElement}. */
    public GTElement multiply(GTElement other) {
        Objects.requireNonNull(other, "other");
        MemorySegment product = newValue();
        Blst.fp12Mul(product, value, other.value);
        return new GTElement(product);
    }

    MemorySegment value() {
        return value;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj instanceof GTElement other && Blst.fp12IsEqual(value, other.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(toBytes());
    }

    /** {@code <GTElement hex>}, as chia-bls's {@code Debug} output. */
    @Override
    public String toString() {
        return "<GTElement " + HexFormat.of().formatHex(toBytes()) + ">";
    }
}
