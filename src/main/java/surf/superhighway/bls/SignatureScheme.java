package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt32;

import java.util.List;

public interface SignatureScheme {

    /**
     * Converts a given PrivateKey to its associated PublicKey.
     *
     * @param privateKey the private key for which the public key is to be derived.
     * @return the corresponding public key.
     * @throws IllegalArgumentException if privateKey is null.
     */
    PublicKey privateKeyToPublicKey(final PrivateKey privateKey) throws IllegalArgumentException;

    /**
     * Sign the given message using the specified private key and the associated cipher suite.
     *
     * @param privateKey the private key to be used for signing the message.
     * @param message    the message to be signed.
     * @return the signature of the message.
     * @throws IllegalArgumentException if either privateKey or message is null.
     */
    Signature sign(final PrivateKey privateKey, final Bytes message) throws IllegalArgumentException;

    /**
     * Verifies the signature of a message using the provided public key.
     *
     * @param publicKey the public key used for verification.
     * @param message   the message whose signature is to be verified.
     * @param signature the signature to be verified.
     * @return true if the signature is valid, false otherwise.
     * @throws IllegalArgumentException if any of the arguments is null.
     */
    boolean verify(final PublicKey publicKey, final Bytes message, final Signature signature) throws IllegalArgumentException;

    /**
     * Aggregates multiple signatures into a single signature.
     *
     * @param signatures the list of signatures to aggregate.
     * @return the aggregated signature.
     * @throws IllegalArgumentException if the list of signatures is empty or null.
     */
    Signature aggregateSignatures(final List<Signature> signatures) throws IllegalArgumentException;

    /**
     * Aggregates multiple public keys into a single public key.
     *
     * @param publicKeys the list of public keys to aggregate.
     * @return the aggregated public key.
     * @throws IllegalArgumentException if the list of public keys is empty or null.
     */
    PublicKey aggregatePublicKeys(final List<PublicKey> publicKeys) throws IllegalArgumentException;

    /**
     * Verify BLS signature against their corresponding messages and public keys.
     *
     * @param publicKeys A list of public keys corresponding to the signers of the messages.
     * @param messages   A list of messages that were signed. The order of messages should match the order of public keys.
     * @param signature  The aggregated signature that corresponds to the aggregated public keys and messages.
     * @return Returns true if the aggregated signature verification is successful; false otherwise.
     * @throws IllegalArgumentException If the size of the public keys list does not match the size of the messages list or if any of the arguments is null.
     */
    boolean aggregateVerify(final List<PublicKey> publicKeys, final List<Bytes> messages, final Signature signature) throws IllegalArgumentException;

    /**
     * Derives a child private key using the given parent private key and index, as per the EIP-2333 specification.
     *
     * @param parentPrivateKey The parent private key.
     * @param index            The index for child key derivation.
     * @return The derived child private key.
     * @throws IllegalArgumentException If any of the arguments are null.
     */
    PrivateKey deriveChildPrivateKey(final PrivateKey parentPrivateKey, UInt32 index) throws IllegalArgumentException;

    /**
     * Derives an unhardened child private key using the given parent private key and index.
     * The derivation process is based on the public key of the parent and a hashed combination of the parent's
     * serialized public key and the provided index.
     *
     * @param parentPrivateKey The parent private key used for deriving the child.
     * @param index            The index used in the derivation process.
     * @return The derived child private key.
     * @throws IllegalArgumentException if parentPrivateKey or index is null.
     */
    PrivateKey deriveChildPrivateKeyUnhardened(final PrivateKey parentPrivateKey, UInt32 index);

    /**
     * Derives an unhardened child public key using the given parent public key and index.
     * The derivation process involves creating a hash from the parent public key and the provided index,
     * then forming a private key from that hash. The child public key is then created by scaling a generator
     * point with this private key and adding it to the parent public key.
     *
     * @param parentPublicKey The parent public key used for deriving the child.
     * @param index           The index used in the derivation process.
     * @return The derived child public key.
     * @throws IllegalArgumentException if publicKey or index is null.
     */
    PublicKey deriveChildPublicKeyUnhardened(final PublicKey parentPublicKey, UInt32 index);

    /**
     * Derives an unhardened child signature using the given parent signature and index.
     * The derivation process involves creating a hash from the parent signature and the provided index,
     * then forming a scalar nonce from that hash. The child signature is then created by scaling a generator
     * point with this nonce and adding it to the parent signature.
     *
     * @param signature The parent signature used for deriving the child signature.
     * @param index     The index used in the derivation process.
     * @return The derived child signature.
     * @throws IllegalArgumentException if signature or index is null.
     */
    Signature deriveChildSignatureUnhardened(final Signature signature, UInt32 index);
}
