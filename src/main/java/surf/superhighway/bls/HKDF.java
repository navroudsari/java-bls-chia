package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt32;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.util.Objects;

@SuppressWarnings("SpellCheckingInspection")
public class HKDF {

    private HKDF() {
        throw new AssertionError("HKDF class should not be instantiated.");
    }

    /**
     * Performs the Extract and Expand phases of the HKDF (HMAC-based Key Derivation Function) using SHA-256.
     *
     * @param salt         The optional salt value (a non-secret random value);
     *                     if not provided, it is set to a string of HashLen zeros.
     * @param ikm          The input keying material. Cannot be null.
     * @param info         Optional context and application-specific information.
     *                     Can be an empty string.
     * @param outputLength The length of the output keying material in bytes.
     * @return The output keying material (OKM) as a byte array.
     * @throws IllegalArgumentException if any of the input parameters is null.
     * @throws IllegalStateException    if the requested output length is too long.
     */
    @SuppressWarnings("SpellCheckingInspection")
    public static Bytes ExtractExpand(final Bytes salt, final Bytes ikm, final Bytes info, UInt32 outputLength) {

        if (Objects.isNull(salt)) {
            throw new IllegalArgumentException("salt cannot be null");
        }
        if (Objects.isNull(ikm)) {
            throw new IllegalArgumentException("ikm cannot be null");
        }
        if (Objects.isNull(info)) {
            throw new IllegalArgumentException("info cannot be null");
        }
        if (Objects.isNull(outputLength)) {
            throw new IllegalArgumentException("outputLength cannot be null");
        }

        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(new SHA256Digest());

        HKDFParameters hkdfParams = new HKDFParameters(ikm.toArray(), salt.toArray(), info.toArray());
        hkdfBytesGenerator.init(hkdfParams);
        byte[] output = new byte[outputLength.intValue()];
        int generatedLength = hkdfBytesGenerator.generateBytes(output, 0, outputLength.intValue());

        if (generatedLength != outputLength.intValue()) {
            throw new IllegalStateException("Generated bytes do not match the requested output length");
        }

        return Bytes.secure(output);
    }
}
