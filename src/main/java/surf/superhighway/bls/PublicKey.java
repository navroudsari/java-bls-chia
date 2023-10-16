package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.Bytes48;
import org.apache.tuweni.units.bigints.UInt32;
import surf.superhighway.util.Util;
import supranational.blst.P1;
import supranational.blst.Scalar;

import java.util.Arrays;
import java.util.Objects;

public class PublicKey {

    public static final PublicKey ZERO = new PublicKey(new P1());

    final P1 point;

    PublicKey(P1 publicKeyPoint) {
        this.point = publicKeyPoint;
    }

    public static PublicKey generate() {
        return new PublicKey(P1.generator());
    }

    /**
     * Constructs a PublicKey from the given bytes.
     *
     * @param bytes The bytes to be converted to a PublicKey.
     * @return The constructed PublicKey.
     * @throws IllegalArgumentException If the input bytes are null or invalid for a PublicKey.
     */
    public static PublicKey fromBytes(Bytes48 bytes) {
        if (Objects.isNull(bytes)) {
            throw new IllegalArgumentException("Input bytes cannot be null.");
        }

        PublicKey publicKey = new PublicKey(new P1(bytes.toArray()));
        if (!publicKey.isValid()) {
            throw new IllegalArgumentException("PublicKey is invalid");
        }

        return publicKey;
    }

    /**
     * Constructs a PublicKey from the given bytes without checking validity.
     *
     * @param bytes The bytes to be converted to a PublicKey.
     * @return The constructed PublicKey.
     * @throws IllegalArgumentException If the input bytes are null.
     */
    public static PublicKey fromBytesUnchecked(Bytes48 bytes) {
        if (Objects.isNull(bytes)) {
            throw new IllegalArgumentException("Input bytes cannot be null.");
        }

        P1 point = new P1(bytes.toArray());

        return new PublicKey(point);
    }

    /**
     * Creates a copy of the current PublicKey instance.
     *
     * @return A new PublicKey instance that is a copy of the current one.
     * @throws IllegalArgumentException If the internal point data is null.
     */
    public PublicKey copy() {
        if (Objects.isNull(point)) {
            throw new IllegalArgumentException("Internal point data cannot be null.");
        }

        return new PublicKey(point.dup());
    }


    /**
     * Serializes the PublicKey instance into a byte representation.
     *
     * @return A Bytes48 representation of the PublicKey.
     * @throws IllegalArgumentException If the internal point data is null.
     */
    public Bytes48 serialize() {
        if (Objects.isNull(point)) {
            throw new IllegalArgumentException("Internal point data cannot be null.");
        }

        return Bytes48.wrap(point.compress());
    }


    /**
     * Calculates the fingerprint for the PublicKey instance.
     *
     * @return A UInt32 representation of the fingerprint.
     * @throws IllegalArgumentException If the serialized representation of the PublicKey is invalid.
     */
    public UInt32 getFingerprint() {
        Bytes32 hash;
        try {
            hash = Bytes32.wrap(Util.hash256(serialize()));
        } catch (Exception e) {
            throw new IllegalArgumentException("Error while hashing serialized PublicKey.", e);
        }

        return Util.fourBytesToInt(hash);
    }

    /**
     * Calculates the fingerprint for the PublicKey instance and returns it as a decimal string.
     *
     * @return A decimal string representation of the fingerprint.
     * @throws IllegalArgumentException If the serialized representation of the PublicKey is invalid.
     */
    public String getFingerprintAsDecimalString() {
        Bytes32 hash;
        try {
            hash = Bytes32.wrap(Util.hash256(serialize()));
        } catch (Exception e) {
            throw new IllegalArgumentException("Error while hashing serialized PublicKey.", e);
        }

        return Util.fourBytesToInt(hash).toDecimalString();
    }

    /**
     * Calculates the fingerprint for the PublicKey instance and returns it as a hexadecimal string.
     *
     * @return A hexadecimal string representation of the fingerprint.
     * @throws IllegalArgumentException If the serialized representation of the PublicKey is invalid.
     */
    public String getFingerprintAsHexString() {
        Bytes32 hash;
        try {
            hash = Bytes32.wrap(Util.hash256(serialize()));
        } catch (Exception e) {
            throw new IllegalArgumentException("Error while hashing serialized PublicKey.", e);
        }

        return Util.fourBytesToInt(hash).toHexString();
    }

    /**
     * Negates the current public key.
     * <p>
     * This method will negate the elliptic curve point associated with the public key,
     * effectively computing the additive inverse on the curve.
     * </p>
     *
     * @return A new PublicKey object representing the negated public key.
     * @throws IllegalArgumentException if the internal point representation is null.
     */
    public PublicKey negate() {
        if (point == null) {
            throw new IllegalArgumentException("Public key's point representation cannot be null.");
        }

        P1 negatedPoint = point.dup();
        negatedPoint.neg();

        return new PublicKey(negatedPoint);
    }


    /**
     * Adds the provided PublicKey to the current public key.
     * <p>
     * This method will add the elliptic curve points associated with the two public keys,
     * effectively computing the additive combination on the curve.
     * </p>
     *
     * @param other The PublicKey to add to the current public key.
     * @return A new PublicKey object representing the sum of the two public keys.
     * @throws IllegalArgumentException if the provided PublicKey is null or its internal point representation is null.
     */
    public PublicKey add(PublicKey other) {

        if (Objects.isNull(other)) {
            throw new IllegalArgumentException("The provided PublicKey cannot be null.");
        }

        if (Objects.isNull(point) || Objects.isNull(other.point)) {
            throw new IllegalArgumentException("The provided PublicKey or its internal point representation cannot be null.");
        }

        P1 resultPoint = point.dup().add(other.point);

        return new PublicKey(resultPoint);
    }


    /**
     * Multiplies this PublicKey's point by another PublicKey's point.
     *
     * @param other The PublicKey by which this PublicKey's point will be multiplied.
     * @return A new PublicKey instance representing the product of this PublicKey's point and the provided one.
     * @throws IllegalArgumentException If the provided PublicKey is null.
     */
    public PublicKey multiply(PublicKey other) {
        if (Objects.isNull(other)) {
            throw new IllegalArgumentException("The provided PublicKey cannot be null.");
        }

        if (Objects.isNull(point) || Objects.isNull(other.point)) {
            throw new IllegalArgumentException("The provided PublicKey or its internal point representation cannot be null.");
        }

        Scalar otherPointScalar = new Scalar();
        otherPointScalar.from_bendian(other.point.serialize());
        P1 resultPoint = point.dup().mult(otherPointScalar);

        return new PublicKey(resultPoint);
    }

    /**
     * Determines if the current point is a valid element of the G1 elliptic curve group.
     * <p>
     * A point is considered valid if it belongs to the G1 group or if it represents the
     * point at infinity (based on historical compatibility with older Relic versions).
     * </p>
     *
     * @return true if the point is valid, false otherwise.
     */
    public boolean isValid() {

        // https://github.com/Chia-Network/bls-signatures/blob/7f10927337a1903f8295f68e6d16b6b3c478667a/src/elements.cpp#L125
        // Infinity was considered a valid G1Element in older Relic versions
        // on which chia bls signatures library was previously based.
        // For historical compatibility this behavior is maintained.
        if (point.is_inf()) {
            return true;
        }

        return point.in_group();
    }


    /**
     * Returns a hexadecimal string representation of this PublicKey instance.
     *
     * @return A string containing the hexadecimal representation of the serialized PublicKey.
     */
    @Override
    public String toString() {
        return serialize().toHexString();
    }


    /**
     * Determines whether the given object is a PublicKey and has the same point value as this PublicKey.
     *
     * @param obj The object to be compared with this PublicKey.
     * @return True if the object is a PublicKey and has the same point value, otherwise false.
     */
    @Override
    public boolean equals(Object obj) {
        if (Objects.isNull(obj)) {
            throw new IllegalArgumentException("The provided object cannot be null.");
        }

        if (!(obj instanceof PublicKey otherPublicKey)) {
            return false;
        }

        return point.is_equal(otherPublicKey.point);
    }

    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + (point != null ? Arrays.hashCode(point.serialize()) : 0);
        return result;
    }


}
