package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt32;
import surf.superhighway.util.Util;
import supranational.blst.SecretKey;

import java.util.Objects;

public class HDKeys {

    public static final int HASH_LENGTH = 32;

    private HDKeys() {
        throw new AssertionError("HDKeys class should not be instantiated.");
    }

    /**
     * Generates a private key based on the provided seed as per the version 3 key generation method.
     *
     * @param seed The seed from which the private key is derived. Must be at least 32 bytes.
     * @return The generated {@link PrivateKey} object.
     * @throws IllegalArgumentException if seed is null or less than 32 bytes in length.
     */
    public static PrivateKey keygen(Bytes seed) {

        if (Objects.isNull(seed)) {
            throw new IllegalArgumentException("seed cannot be null");
        }

        if (seed.size() < HASH_LENGTH) {
            throw new IllegalArgumentException("Seed size must be at least " + HASH_LENGTH + " bytes");
        }

        SecretKey blstSecretKey = new SecretKey();
        blstSecretKey.keygen_v3(seed.toArray());

        return PrivateKey.fromBytes(Bytes32.secure(blstSecretKey.to_bendian()));
    }

    /**
     * Computes a Lamport public key based on the provided parent private key and an index.
     *
     * @param parentPrivateKey The parent private key used in generating the Lamport key.
     * @param index            The index used as a salt for key derivation.
     * @return The computed Lamport {@link PublicKey}.
     * @throws IllegalArgumentException if parentPk or index is null.
     */
    public static Bytes32 parentSKToLamportPK(PrivateKey parentPrivateKey, UInt32 index) {

        if (Objects.isNull(parentPrivateKey)) {
            throw new IllegalArgumentException("parentPk cannot be null");
        }
        if (Objects.isNull(index)) {
            throw new IllegalArgumentException("index cannot be null");
        }

        UInt32 outputLength = UInt32.valueOf(HASH_LENGTH * 255);
        Bytes salt = Util.intTofourBytes(index);
        Bytes ikm = parentPrivateKey.serialize();

        Bytes notIkm = ikm.not();
        Bytes lamport0 = HKDF.ExtractExpand(salt, ikm, Bytes.EMPTY, outputLength);
        Bytes lamport1 = HKDF.ExtractExpand(salt, notIkm, Bytes.EMPTY, outputLength);

        assert (4 == salt.size());
        assert (HASH_LENGTH == ikm.size());
        assert (HASH_LENGTH == notIkm.size());
        assert (HASH_LENGTH * 255 == lamport0.size());
        assert (HASH_LENGTH * 255 == lamport1.size());

        Bytes lamportPK = Bytes.EMPTY;
        for (int i = 0; i < 255; i++) {
            int startIndex = i * HASH_LENGTH;
            lamportPK = Bytes.concatenate(lamportPK, Util.hash256(lamport0.slice(startIndex, HASH_LENGTH)));
        }

        for (int i = 0; i < 255; i++) {
            int startIndex = i * HASH_LENGTH;
            lamportPK = Bytes.concatenate(lamportPK, Util.hash256(lamport1.slice(startIndex, HASH_LENGTH)));
        }

        return Util.hash256(lamportPK);
    }

    /**
     * Derives a child private key from the given parent private key and index using the Lamport scheme.
     *
     * @param parentPrivateKey The parent private key used for child key derivation.
     * @param index            The index to assist in child key derivation.
     * @return The derived child {@link PrivateKey}.
     * @throws IllegalArgumentException if parentPrivateKey or index is null.
     */
    public static PrivateKey deriveChildSk(final PrivateKey parentPrivateKey, UInt32 index) {

        if (Objects.isNull(parentPrivateKey)) {
            throw new IllegalArgumentException("parentPrivateKey cannot be null");
        }
        if (Objects.isNull(index)) {
            throw new IllegalArgumentException("index cannot be null");
        }

        Bytes32 lamportPk = parentSKToLamportPK(parentPrivateKey, index);

        return keygen(lamportPk);
    }

}
