package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.Bytes48;
import supranational.blst.P1;
import supranational.blst.P2;
import supranational.blst.Scalar;
import supranational.blst.SecretKey;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

@SuppressWarnings("SpellCheckingInspection")
public class PrivateKey {

    public static final int SIZE = 32;
    public static final PrivateKey ZERO = new PrivateKey(new SecretKey());

    private static final BigInteger BLS12_381_r = new BigInteger("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001", 16);
    final SecretKey blstSecretKey;

    private PrivateKey(SecretKey blstSecretKey) {
        this.blstSecretKey = blstSecretKey;
    }

    /**
     * Constructs a private key from the given byte array.
     *
     * @param bytes    The byte array to convert into a PrivateKey.
     *                 The size of this array should be at least SIZE bytes.
     * @param modOrder If true, the method will first interpret the bytes as a scalar (mod order)
     *                 before constructing the private key. Otherwise, it will use the bytes as-is.
     * @return A new instance of PrivateKey.
     * @throws IllegalArgumentException if the size of the byte array is less than SIZE or if the provided byte array is null.
     * @throws AssertionError           if the size of the provided byte sequence is less than the expected size.
     */
    private static PrivateKey fromBytes(Bytes32 bytes, boolean modOrder) {

        if (Objects.isNull(bytes)) {
            throw new IllegalStateException("bytes cannot be null");
        }

        if (bytes.size() < SIZE) {
            throw new AssertionError("Seed size must be at least " + SIZE + " bytes");
        }

        SecretKey blstSecretKey = new SecretKey();
        if (modOrder) {
            Scalar scalar = new Scalar().from_bendian(bytes.toArray());
            blstSecretKey.from_bendian(scalar.to_bendian());
        } else {
            blstSecretKey.from_bendian(bytes.toArray());
        }

        if (!keyCheck(Bytes32.secure(blstSecretKey.to_bendian()))) {
            throw new IllegalStateException("PrivateKey byte data must be less than the group order");
        }

        return new PrivateKey(blstSecretKey);
    }

    /**
     * Constructs a private key instance from the provided byte sequence.
     *
     * <p>This function creates a private key without adjusting its value modulo
     * the order of the curve's base point. As a result, the input byte sequence
     * is directly used as the private key.</p>
     *
     * @param bytes The byte sequence to derive the PrivateKey from.
     * @return A new instance of PrivateKey.
     */
    public static PrivateKey fromBytes(Bytes32 bytes) {
        return fromBytes(bytes, false);
    }

    /**
     * Constructs a private key instance from the provided byte sequence,
     * ensuring that the resultant private key value is taken modulo the order of
     * the curve's base point.
     *
     * <p>This ensures that the resultant private key value remains within the
     * valid range of the elliptic curve.</p>
     *
     * @param bytes The byte sequence to derive the PrivateKey from.
     * @return A new instance of PrivateKey.
     */
    public static PrivateKey fromBytesModOrder(Bytes32 bytes) {
        return fromBytes(bytes, true);
    }

    /**
     * Aggregates a list of private keys into a single private key.
     *
     * @param privateKeys The list of private keys to be aggregated.
     * @return The aggregated PrivateKey.
     * @throws IllegalArgumentException if the provided list is null or empty,
     *                                  or if any private key in the list is null or has a null blstSecretKey.
     * @throws VerifyError              if the number of private keys is zero.
     */
    public static PrivateKey aggregate(final List<PrivateKey> privateKeys) {
        if (Objects.isNull(privateKeys) || privateKeys.isEmpty()) {
            throw new IllegalArgumentException("List of private keys cannot be null or empty.");
        }

        Scalar keyData = new Scalar();
        for (PrivateKey privateKey : privateKeys) {
            if (Objects.isNull(privateKey) || Objects.isNull(privateKey.blstSecretKey)) {
                throw new IllegalArgumentException("Invalid private key found in the list. Neither a private key nor its underlying representation can be null.");
            }
            keyData.add(privateKey.blstSecretKey);
        }

        return PrivateKey.fromBytes(Bytes32.secure(keyData.to_bendian()), false);
    }

    /**
     * Checks if the given key data is less than or equal to the defined BLS12-381_r value.
     *
     * @param keydata The Bytes32 representation of the key data to check.
     * @return true if the key data is less than or equal to BLS12_381_r, false otherwise.
     */
    private static boolean keyCheck(Bytes32 keydata) {
        // Prepend a zero byte to the key data to ensure the resulting BigInteger is positive.
        Bytes positiveBytes = Bytes.concatenate(Bytes.of(0), keydata);
        BigInteger data = positiveBytes.toBigInteger();
        return data.compareTo(BLS12_381_r) <= 0;
    }

    /**
     * Derives the corresponding PublicKey from this PrivateKey.
     *
     * @return The associated {@link PublicKey}.
     * @throws IllegalStateException if the underlying private key representation is null.
     */
    protected PublicKey getPublicKey() {
        if (Objects.isNull(blstSecretKey)) {
            throw new IllegalStateException("Underlying secret key cannot be null");
        }
        P1 point = new P1(blstSecretKey);

        return PublicKey.fromBytes(Bytes48.wrap(point.compress()));
    }

    /**
     * Generates a signature representation using the underlying secret key.
     * <p>
     * This method compresses the secret key into a byte array and then constructs a
     * {@link Signature} from those bytes.
     * </p>
     *
     * @return the generated {@link Signature} object.
     * @throws IllegalStateException if the underlying secret key is null.
     */
    public Signature getSignature() {
        if (Objects.isNull(blstSecretKey)) {
            throw new IllegalStateException("Underlying secret key cannot be null");
        }
        P2 point = new P2(blstSecretKey);

        return Signature.fromBytes(Bytes.wrap(point.compress()));
    }

    /**
     * Signs the given message using the G2 curve and produces a Signature.
     *
     * @param msg The message to be signed.
     * @param dst Domain separation tag, used to separate the context of different signature uses.
     * @return The produced {@link Signature}.
     * @throws IllegalArgumentException if the message, dst, or underlying private key representation is null.
     */
    public Signature signG2(Bytes msg, String dst) {

        if (Objects.isNull(msg)) {
            throw new IllegalArgumentException("Message to be signed cannot be null.");
        }
        if (Objects.isNull(dst)) {
            throw new IllegalArgumentException("Domain separation tag cannot be null.");
        }
        if (Objects.isNull(blstSecretKey)) {
            throw new IllegalArgumentException("Underlying secret key representation cannot be null.");
        }

        P2 point = P2.generator().hash_to(msg.toArray(), dst, null);
        point = point.sign_with(blstSecretKey);
        return new Signature(point);
    }

    /**
     * Creates a deep copy of this PrivateKey instance.
     *
     * @return A new PrivateKey instance with a copy of the underlying secret key.
     * @throws IllegalArgumentException if the internal representation (blstSecretKey) of the private key is null.
     */
    public PrivateKey copy() {
        if (Objects.isNull(blstSecretKey)) {
            throw new IllegalArgumentException("Internal representation of the private key cannot be null.");
        }
        return new PrivateKey(blstSecretKey.dup());
    }

    /**
     * Serializes the private key into a big-endian representation wrapped in a Bytes32 object.
     *
     * @return The serialized representation of the private key.
     * @throws IllegalArgumentException if the private key data (blstSecretKey) is null.
     */
    public Bytes32 serialize() {
        if (Objects.isNull(blstSecretKey)) {
            throw new IllegalArgumentException("Private key data cannot be null.");
        }
        return Bytes32.secure(blstSecretKey.to_bendian());
    }

    /**
     * Returns the hexadecimal string representation of the serialized private key.
     *
     * @return The hex string representation of the private key.
     * @throws IllegalArgumentException if the serialized private key is null.
     */
    @Override
    public String toString() {
        Bytes32 serializedKey = serialize();
        if (Objects.isNull(serializedKey)) {
            throw new IllegalArgumentException("Serialized private key cannot be null.");
        }
        return serializedKey.toHexString();
    }


    /**
     * Determines whether the given object is equivalent to this PrivateKey.
     *
     * @param obj The object to compare against.
     * @return true if the provided object is a PrivateKey and has the same serialization
     * and associated public key; false otherwise.
     */
    @Override
    public boolean equals(Object obj) {
        // Check for same object reference for a quick true result
        if (this == obj) {
            return true;
        }

        // Check for appropriate type and pattern match to variable otherPrivateKey
        if (!(obj instanceof PrivateKey otherPrivateKey)) {
            return false;
        }

        // Compare serialized private key and associated public keys
        return serialize().equals(otherPrivateKey.serialize()) && Objects.equals(getPublicKey(), otherPrivateKey.getPublicKey());
    }

    @Override
    public int hashCode() {
        return Objects.hash(serialize(), getPublicKey());
    }

}
