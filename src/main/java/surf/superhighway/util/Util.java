package surf.superhighway.util;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt32;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class Util {

    private Util() {
        throw new AssertionError("Util class should not be instantiated.");
    }

    /**
     * Computes the SHA-256 hash of the given message.
     *
     * @param message The input data to be hashed. Must not be null.
     * @return A Bytes32 object representing the SHA-256 hash of the message.
     * @throws IllegalArgumentException If the provided message is null.
     * @throws RuntimeException         If the SHA-256 MessageDigest is not available on the platform.
     */
    public static Bytes32 hash256(Bytes message) {
        if (Objects.isNull(message)) {
            throw new IllegalArgumentException("Provided message cannot be null.");
        }

        MessageDigest sha256Digest;
        try {
            sha256Digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm is not available.", e);
        }

        return Bytes32.secure(sha256Digest.digest(message.toArray()));
    }

    /**
     * Converts the first 4 bytes of the given Bytes object into an UInt32 value.
     *
     * @param bytes The Bytes object. It must have at least 4 bytes.
     * @return The UInt32 representation of the first 4 bytes of the given Bytes object.
     * @throws IllegalArgumentException If the provided Bytes object is null or has less than 4 bytes.
     */
    public static UInt32 fourBytesToInt(Bytes bytes) {
        if (Objects.isNull(bytes)) {
            throw new IllegalArgumentException("Provided bytes cannot be null.");
        }

        if (bytes.size() < 4) {
            throw new IllegalArgumentException("Provided bytes must have at least 4 bytes.");
        }

        return UInt32.fromBytes(bytes.slice(0, 4));
    }

    /**
     * Converts the given UInt32 value into a Bytes object of length 4.
     *
     * @param uInt32 The UInt32 value to convert. Must not be null.
     * @return A Bytes object of length 4 representing the given UInt32 value.
     * @throws IllegalArgumentException If the provided UInt32 object is null.
     */
    public static Bytes intTofourBytes(UInt32 uInt32) {
        if (Objects.isNull(uInt32)) {
            throw new IllegalArgumentException("Provided uInt32 cannot be null.");
        }

        Bytes result = uInt32.toBytes().trimLeadingZeros();
        int paddingLength = 4 - result.size();

        if (paddingLength > 0) {
            // Pad with zeros at the beginning to make it 4 bytes long
            return Bytes.concatenate(Bytes.wrap(new byte[paddingLength]), result);
        }
        return result;
    }

}
