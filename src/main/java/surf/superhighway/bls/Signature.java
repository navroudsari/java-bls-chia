package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import supranational.blst.P2;
import supranational.blst.Scalar;

import java.util.Arrays;
import java.util.Objects;

public class Signature {

    public static final int SIZE = 96;
    public static final Signature ZERO = new Signature(new P2());
    final P2 point;

    Signature(P2 point) {
        this.point = point;
    }

    public static Signature generate() {
        return new Signature(P2.generator());
    }

    /**
     * Creates a Signature instance from the given byte array representation.
     *
     * @param bytes The byte representation of the signature.
     * @return The constructed Signature instance.
     * @throws IllegalArgumentException if the byte representation is not of the expected size, is null, or is invalid.
     */
    public static Signature fromBytes(Bytes bytes) {
        if (Objects.isNull(bytes)) {
            throw new IllegalArgumentException("Bytes representation cannot be null.");
        }
        if (bytes.size() != SIZE) {
            throw new IllegalArgumentException("Byte representation size must be " + SIZE);
        }

        P2 point;
        try {
            point = new P2(bytes.toArray());
        } catch (RuntimeException ex) {
            throw new IllegalArgumentException("Signature is invalid");
        }

        return new Signature(point);
    }

    /**
     * Serializes the public key to its compressed form.
     *
     * @return The serialized byte representation of the public key.
     * @throws IllegalArgumentException if the public key's point is null.
     */
    public Bytes serialize() {
        if (Objects.isNull(point)) {
            throw new IllegalArgumentException("Public key's point cannot be null.");
        }

        return Bytes.wrap(point.compress());
    }

    /**
     * Negates the current Signature.
     * <p>
     * This method computes the negation of the elliptic curve point associated with the signature.
     * </p>
     *
     * @return A new Signature object representing the negated value of the current signature.
     * @throws IllegalArgumentException if the internal point representation of the signature is null.
     */
    public Signature negate() {
        if (point == null) {
            throw new IllegalArgumentException("Signature's point representation cannot be null.");
        }

        P2 negatedPoint = point.dup().neg();

        return new Signature(negatedPoint);
    }

    /**
     * Adds the given Signature's point to the current Signature's point and returns a new Signature.
     *
     * @param other The other Signature to add to the current one.
     * @return A new Signature resulting from the addition.
     * @throws IllegalArgumentException if the provided Signature is null.
     */
    public Signature add(Signature other) {
        if (Objects.isNull(other)) {
            throw new IllegalArgumentException("The provided Signature cannot be null.");
        }

        if (Objects.isNull(point) || Objects.isNull(other.point)) {
            throw new IllegalArgumentException("The provided Signature or its internal point representation cannot be null.");
        }

        P2 resultPoint = point.dup().add(other.point);
        return new Signature(resultPoint);
    }

    /**
     * Multiplies the current Signature with another given Signature.
     * <p>
     * This method computes the elliptic curve point multiplication between the current signature's point
     * and the serialized form of the provided signature's point.
     * </p>
     *
     * @param other The Signature to be multiplied with the current Signature.
     * @return A new Signature object representing the product of the two Signatures.
     * @throws IllegalArgumentException if the provided Signature is null or if its internal point representation is null.
     */
    public Signature multiply(Signature other) {

        if (Objects.isNull(other)) {
            throw new IllegalArgumentException("The provided Signature cannot be null.");
        }

        if (Objects.isNull(point) || Objects.isNull(other.point)) {
            throw new IllegalArgumentException("The provided Signature or its internal point representation cannot be null.");
        }

        Scalar otherPointScalar = new Scalar();
        otherPointScalar.from_bendian(other.point.serialize());
        P2 resultPoint = point.dup().mult(otherPointScalar);

        return new Signature(resultPoint);
    }


    /**
     * Creates a deep copy of the current Signature instance.
     *
     * @return A new Signature instance that is a copy of the current one.
     * @throws IllegalArgumentException if the internal point is null.
     */
    public Signature copy() {
        if (Objects.isNull(point)) {
            throw new IllegalArgumentException("Internal point of the Signature cannot be null.");
        }

        return new Signature(point.dup());
    }

    /**
     * Determines if the current point is a valid element of the G2 elliptic curve group.
     * <p>
     * A point is considered valid if it belongs to the G2 group or if it represents the
     * point at infinity (based on historical compatibility with older Relic versions).
     * </p>
     *
     * @return true if the point is valid, false otherwise.
     */
    public boolean isValid() {

        // https://github.com/Chia-Network/bls-signatures/blob/7f10927337a1903f8295f68e6d16b6b3c478667a/src/elements.cpp#L297
        // Infinity was considered a valid G2Element in older Relic versions
        // on which chia bls signatures library was previously based.
        // For historical compatibility this behavior is maintained.
        if (point.is_inf()) {
            return true;
        }

        return point.in_group();
    }

    /**
     * Returns a hexadecimal string representation of the serialized signature.
     *
     * @return A string in hexadecimal format representing the serialized signature.
     * @throws IllegalArgumentException if the serialized data is null.
     */
    @Override
    public String toString() {
        Bytes serializedData = serialize();
        if (Objects.isNull(serializedData)) {
            throw new IllegalArgumentException("Serialization of the signature resulted in a null value.");
        }

        return serializedData.toHexString();
    }


    /**
     * Determines whether the given object is equal to this Signature.
     *
     * @param obj The object to be compared.
     * @return True if the given object is a Signature and its underlying point matches this Signature's point, false otherwise.
     * @throws IllegalArgumentException if the point of this signature is null.
     */
    @Override
    public boolean equals(Object obj) {
        if (Objects.isNull(point)) {
            throw new IllegalArgumentException("The point of this signature is null.");
        }

        if (!(obj instanceof Signature otherSignature)) {
            return false;
        }

        return point.is_equal(otherSignature.point);
    }

    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + (point != null ? Arrays.hashCode(point.serialize()) : 0);
        return result;
    }


}
