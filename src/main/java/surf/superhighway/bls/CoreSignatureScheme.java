package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.Bytes48;
import org.apache.tuweni.units.bigints.UInt32;
import surf.superhighway.util.Util;
import supranational.blst.*;

import java.util.List;
import java.util.Objects;


public abstract class CoreSignatureScheme implements SignatureScheme {

    final CipherSuiteID cipherSuiteID;

    CoreSignatureScheme(CipherSuiteID cipherSuiteID) {
        this.cipherSuiteID = cipherSuiteID;
    }

    /**
     * Generates a PrivateKey based on a given seed.
     *
     * @param seed the seed used for key generation. Must be at least PrivateKey.SIZE bytes.
     * @return the generated {@link PrivateKey}.
     * @throws IllegalArgumentException if the seed size is smaller than PrivateKey.SIZE or null.
     */
    public static PrivateKey keygen(final Bytes seed) {
        if (Objects.isNull(seed)) {
            throw new IllegalArgumentException("seed cannot be null");
        }

        // Required by the ietf spec to be at least 32 bytes
        if (seed.size() < PrivateKey.SIZE) {
            throw new IllegalArgumentException("Seed size must be at least " + PrivateKey.SIZE + "  bytes");
        }
        SecretKey blstSecretKey = new SecretKey();
        blstSecretKey.keygen_v3(seed.toArray());

        return PrivateKey.fromBytes(Bytes32.secure(blstSecretKey.to_bendian()));
    }

    /**
     * Converts a given PrivateKey to its associated PublicKey.
     *
     * @param privateKey the private key for which the public key is to be derived.
     * @return the corresponding {@link PublicKey}.
     * @throws IllegalArgumentException if privateKey is null.
     */
    @Override
    public PublicKey privateKeyToPublicKey(final PrivateKey privateKey) {
        if (Objects.isNull(privateKey)) {
            throw new IllegalArgumentException("privateKey cannot be null");
        }

        return privateKey.getPublicKey();
    }

    /**
     * Sign the given message using the specified private key and the associated cipher suite.
     *
     * @param privateKey the private key to be used for signing the message.
     * @param message    the message to be signed.
     * @return the {@link Signature} of the message.
     * @throws IllegalArgumentException if either privateKey or message is null.
     */
    @Override
    public Signature sign(final PrivateKey privateKey, final Bytes message) {
        if (Objects.isNull(privateKey)) {
            throw new IllegalArgumentException("privateKey cannot be null");
        }

        if (Objects.isNull(message)) {
            throw new IllegalArgumentException("message cannot be null");
        }

        return privateKey.signG2(message, cipherSuiteID.getStringValue());
    }


    /**
     * Verifies the signature of a message using the provided public key.
     *
     * @param publicKey the public key used for verification.
     * @param message   the message whose signature is to be verified.
     * @param signature the signature to be verified.
     * @return true if the signature is valid, false otherwise.
     * @throws IllegalArgumentException if any of the arguments is null.
     */
    @Override
    public boolean verify(final PublicKey publicKey, final Bytes message, final Signature signature) {
        if (Objects.isNull(publicKey)) {
            throw new IllegalArgumentException("publicKey cannot be null");
        }

        if (Objects.isNull(message)) {
            throw new IllegalArgumentException("message cannot be null");
        }

        if (Objects.isNull(signature)) {
            throw new IllegalArgumentException("signature cannot be null");
        }

        P1_Affine pkAffine = publicKey.point.to_affine();
        P2_Affine sigAffine = signature.point.to_affine();

        return sigAffine.core_verify(pkAffine, true, message.toArray(), cipherSuiteID.getStringValue()) == BLST_ERROR.BLST_SUCCESS;
    }

    /**
     * Aggregates multiple signatures into a single signature.
     *
     * @param signatures the list of signatures to aggregate.
     * @return the aggregated {@link Signature}.
     * @throws IllegalArgumentException if the list of signatures is empty or null.
     */
    @Override
    public Signature aggregateSignatures(final List<Signature> signatures) {
        if (Objects.isNull(signatures)) {
            throw new IllegalArgumentException("List of signatures cannot be null");
        }

        if (signatures.isEmpty()) {
            throw new IllegalArgumentException("List of signatures cannot be empty");
        }

        P2 aggregated = signatures.stream().map(signature -> signature.point).reduce(new P2(), P2::add);

        return new Signature(aggregated);
    }

    /**
     * Aggregates multiple public keys into a single public key.
     *
     * @param publicKeys the list of public keys to aggregate.
     * @return the aggregated {@link PublicKey}.
     * @throws IllegalArgumentException if the list of public keys is empty or null.
     */
    @Override
    public PublicKey aggregatePublicKeys(final List<PublicKey> publicKeys) {
        if (Objects.isNull(publicKeys)) {
            throw new IllegalArgumentException("List of publicKeys cannot be null");
        }

        if (publicKeys.isEmpty()) {
            throw new IllegalArgumentException("List of public keys cannot be empty");
        }

        P1 aggregated = publicKeys.stream().map(publicKey -> publicKey.point).reduce(new P1(), P1::add);

        return PublicKey.fromBytes(Bytes48.wrap(aggregated.compress()));
    }

    /**
     * Verify BLS signature against their corresponding messages and public keys.
     *
     * @param publicKeys A list of public keys corresponding to the signers of the messages.
     * @param messages   A list of messages that were signed. The order of messages should match the order of public keys.
     * @param signature  The aggregated signature that corresponds to the aggregated public keys and messages.
     * @return Returns true if the aggregated signature verification is successful; false otherwise.
     * @throws IllegalArgumentException If the size of the public keys list does not match the size of the messages list or if any of the arguments is null.
     */
    @Override
    public boolean aggregateVerify(final List<PublicKey> publicKeys, final List<Bytes> messages, final Signature signature) {

        if (Objects.isNull(publicKeys)) {
            throw new IllegalArgumentException("publicKey list cannot be null");
        }

        if (Objects.isNull(messages)) {
            throw new IllegalArgumentException("message list cannot be null");
        }

        if (Objects.isNull(signature)) {
            throw new IllegalArgumentException("signature cannot be null");
        }

        if (publicKeys.size() != messages.size()) {
            throw new IllegalArgumentException("Mismatched sizes for public keys and messages");
        }

        InvariantResult argCheck = verifyAggregateSignatureArguments(publicKeys.size(), messages.size(), signature);
        if (argCheck != InvariantResult.CONTINUE) {
            return argCheck == InvariantResult.GOOD;
        }

        Pairing pairing = new Pairing(true, cipherSuiteID.getStringValue());
        P2_Affine signatureAffine = signature.point.to_affine();
        PT fp12 = new PT(signatureAffine);

        @SuppressWarnings("SpellCheckingInspection") List<P1_Affine> publicKeyAffines = publicKeys.stream().map(pk -> pk.point.to_affine()).toList();

        for (int i = 0; i < publicKeyAffines.size(); i++) {
            P1_Affine publicKeyAffine = publicKeyAffines.get(i);
            Bytes messageBytes = Bytes.secure(messages.get(i).toArray());

            if (pairing.aggregate(publicKeyAffine, signatureAffine, messageBytes.toArray()) != BLST_ERROR.BLST_SUCCESS) {
                return false;
            }
        }

        pairing.commit();
        return pairing.finalverify(fp12);
    }

    /**
     * Derives a child private key using the given parent private key and index, as per the EIP-2333 specification.
     *
     * @param parentPrivateKey The parent private key.
     * @param index            The index for child key derivation.
     * @return The derived child {@link PrivateKey}.
     * @throws IllegalArgumentException If any of the arguments are null.
     */
    @Override
    public PrivateKey deriveChildPrivateKey(final PrivateKey parentPrivateKey, UInt32 index) {

        if (Objects.isNull(parentPrivateKey)) {
            throw new IllegalArgumentException("parentPrivateKey cannot be null");
        }

        if (Objects.isNull(index)) {
            throw new IllegalArgumentException("index cannot be null");
        }

        PrivateKey privateKey = parentPrivateKey.copy();
        parentPrivateKey.blstSecretKey.derive_child_eip2333(privateKey.blstSecretKey, index.toLong());

        return privateKey;
    }

    /**
     * Derives an unhardened child private key using the given parent private key and index.
     * The derivation process is based on the public key of the parent and a hashed combination of the parent's
     * serialized public key and the provided index.
     *
     * @param parentPrivateKey The parent private key used for deriving the child.
     * @param index            The index used in the derivation process.
     * @return The derived child {@link PrivateKey}.
     * @throws IllegalArgumentException if parentPrivateKey or index is null.
     */
    @Override
    public PrivateKey deriveChildPrivateKeyUnhardened(final PrivateKey parentPrivateKey, UInt32 index) {

        if (Objects.isNull(parentPrivateKey)) {
            throw new IllegalArgumentException("parentPrivateKey cannot be null");
        }

        if (Objects.isNull(index)) {
            throw new IllegalArgumentException("index cannot be null");
        }

        PublicKey publicKey = parentPrivateKey.getPublicKey();
        Bytes indexBytes = Util.intTofourBytes(index);
        Bytes32 derivedKeyDigest = Util.hash256(Bytes.concatenate(publicKey.serialize(), indexBytes));

        return PrivateKey.aggregate(List.of(parentPrivateKey, PrivateKey.fromBytesModOrder(derivedKeyDigest)));
    }

    /**
     * Derives an unhardened child public key using the given parent public key and index.
     * The derivation process involves creating a hash from the parent public key and the provided index,
     * then forming a private key from that hash. The child public key is then created by scaling a generator
     * point with this private key and adding it to the parent public key.
     *
     * @param parentPublicKey The parent public key used for deriving the child.
     * @param index           The index used in the derivation process.
     * @return The derived child {@link PublicKey}.
     * @throws IllegalArgumentException if publicKey or index is null.
     */
    @Override
    public PublicKey deriveChildPublicKeyUnhardened(final PublicKey parentPublicKey, UInt32 index) {

        if (Objects.isNull(parentPublicKey)) {
            throw new IllegalArgumentException("publicKey cannot be null");
        }

        if (Objects.isNull(index)) {
            throw new IllegalArgumentException("index cannot be null");
        }

        Bytes indexBytes = Util.intTofourBytes(index);
        Bytes32 digest = Util.hash256(Bytes.wrap(parentPublicKey.serialize(), indexBytes));
        PrivateKey privateKey = PrivateKey.fromBytesModOrder(digest);

        Scalar nonce = new Scalar().from_bendian(privateKey.serialize().toArray());

        return new PublicKey(parentPublicKey.point.add(P1.generator().mult(nonce)));
    }

    /**
     * Derives an unhardened child signature using the given parent signature and index.
     * The derivation process involves creating a hash from the parent signature and the provided index,
     * then forming a scalar nonce from that hash. The child signature is then created by scaling a generator
     * point with this nonce and adding it to the parent signature.
     *
     * @param signature The parent signature used for deriving the child signature.
     * @param index     The index used in the derivation process.
     * @return The derived child {@link Signature}.
     * @throws IllegalArgumentException if signature or index is null.
     */
    @Override
    public Signature deriveChildSignatureUnhardened(final Signature signature, UInt32 index) {

        if (Objects.isNull(signature)) {
            throw new IllegalArgumentException("signature cannot be null");
        }

        if (Objects.isNull(index)) {
            throw new IllegalArgumentException("index cannot be null");
        }

        Bytes indexBytes = Util.intTofourBytes(index);
        Bytes32 digest = Util.hash256(Bytes.wrap(signature.serialize(), indexBytes));
        Scalar nonce = new Scalar().from_lendian(digest.toArray());

        return new Signature(signature.point.add(P2.generator().mult(nonce)));
    }

    /**
     * Verifies the consistency of aggregate signature arguments.
     *
     * <p>
     * The verification checks are as follows:
     * <ul>
     *   <li>If there are no public keys ({@code publicKeyCount} is 0):
     *     <ul>
     *       <li>Returns {@code InvariantResult.GOOD} if there are also no messages
     *           ({@code messageCount} is 0) and the provided signature is equivalent
     *           to the ZERO signature.</li>
     *       <li>Returns {@code InvariantResult.BAD} otherwise.</li>
     *     </ul>
     *   </li>
     *   <li>If there are public keys:
     *     <ul>
     *       <li>Returns {@code InvariantResult.CONTINUE} if the number of public keys
     *           matches the number of messages.</li>
     *       <li>Returns {@code InvariantResult.BAD} otherwise.</li>
     *     </ul>
     *   </li>
     * </ul>
     * </p>
     *
     * @param publicKeyCount The number of public keys involved in the aggregate signature.
     * @param messageCount   The number of messages to be signed or verified.
     * @param signature      The aggregate signature for verification.
     * @return One of the {@code InvariantResult} values depending on the verification outcome.
     */
    InvariantResult verifyAggregateSignatureArguments(int publicKeyCount, int messageCount, Signature signature) {
        if (publicKeyCount == 0) {
            return (messageCount == 0 && signature.equals(Signature.ZERO)) ? InvariantResult.GOOD : InvariantResult.BAD;
        }
        return (publicKeyCount == messageCount) ? InvariantResult.CONTINUE : InvariantResult.BAD;
    }

    /**
     * Enum representing the result of the verification of aggregate signature arguments.
     */
    enum InvariantResult {
        /**
         * Indicates that the verification passed successfully.
         */
        GOOD,
        /**
         * Indicates that the verification failed due to inconsistency in the arguments.
         */
        BAD,
        /**
         * Indicates that the initial checks passed, but further verification or processing
         * is required.
         */
        CONTINUE
    }

}
