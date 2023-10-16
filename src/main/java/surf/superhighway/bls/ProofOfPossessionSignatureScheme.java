package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import supranational.blst.BLST_ERROR;
import supranational.blst.P1_Affine;
import supranational.blst.P2;
import supranational.blst.P2_Affine;

import java.util.List;
import java.util.Objects;

public class ProofOfPossessionSignatureScheme extends CoreSignatureScheme {
    private ProofOfPossessionSignatureScheme() {
        super(CipherSuiteID.BLS_SIG_POP_SCHEME_MPL);
    }

    public static ProofOfPossessionSignatureScheme getInstance() {
        return HOLDER.INSTANCE;
    }

    /**
     * Generates a Proof of Possession (PoP) signature using the given private key.
     * The PoP is a signature over the hash of the public key derived from the private key,
     * demonstrating the prover's knowledge of the private key without revealing it.
     *
     * @param privateKey The private key used to produce the PoP signature.
     * @return The Proof of Possession {@link Signature}.
     * @throws IllegalStateException if the public key cannot be derived from the private key.
     */
    public Signature popProve(final PrivateKey privateKey) {
        if (Objects.isNull(privateKey)) {
            throw new IllegalStateException("privateKey cannot be null");
        }

        PublicKey publicKey = privateKey.getPublicKey();
        if (Objects.isNull(publicKey)) {
            throw new IllegalStateException("Unable to derive public key from the private key");
        }

        byte[] publicKeyBytes = publicKey.serialize().toArray();
        P2 hashPoint = new P2().hash_to(publicKeyBytes, CipherSuiteID.BLS_POP_SCHEME_MPL.getStringValue());

        return new Signature(hashPoint.sign_with(privateKey.blstSecretKey));
    }

    /**
     * Verifies the proof of possession (POP) for a given public key and signature proof.
     *
     * <p>This method checks if the provided signature proof is a valid POP for the
     * given public key using the specific cryptographic mechanisms defined by
     * the underlying library.
     *
     * @param publicKey      the public key whose possession needs to be verified
     * @param signatureProof the signature proof associated with the public key
     * @return true if the POP verification is successful, false otherwise
     * @throws IllegalArgumentException if the provided publicKey or signatureProof is null
     * @throws IllegalStateException    if conversion to affine coordinates fails
     */
    public boolean popVerify(final PublicKey publicKey, final Signature signatureProof) {

        if (Objects.isNull(publicKey)) {
            throw new IllegalStateException("publicKey cannot be null");
        }

        if (Objects.isNull(signatureProof)) {
            throw new IllegalStateException("signatureProof cannot be null");
        }

        P1_Affine publicKeyAffine = publicKey.point.to_affine();
        P2_Affine signatureAffine = signatureProof.point.to_affine();

        if (Objects.isNull(publicKeyAffine) || Objects.isNull(signatureAffine)) {
            throw new IllegalStateException("Failed to convert to affine coordinates.");
        }

        byte[] publicKeyBytes = publicKey.serialize().toArray();

        // Check if the signature proof is a valid POP for the given public key
        return signatureAffine.core_verify(publicKeyAffine, true, publicKeyBytes, CipherSuiteID.BLS_POP_SCHEME_MPL.getStringValue()) == BLST_ERROR.BLST_SUCCESS;
    }

    /**
     * Fast aggregate verification for BLS signatures.
     * <p>
     * This method aggregates multiple public keys into a single one and then verifies
     * the provided message and signature against the aggregated key.
     * </p>
     *
     * @param publicKeys a list of public keys to be aggregated
     * @param message    the message to be verified
     * @param signature  the signature of the message to be verified against the aggregated public key
     * @return true if the verification is successful, false otherwise
     * @throws IllegalArgumentException if the provided publicKeys, message, or signature is null
     */
    public boolean fastAggregateVerify(final List<PublicKey> publicKeys, Bytes message, final Signature signature) {
        if (Objects.isNull(publicKeys)) {
            throw new IllegalStateException("publicKeys list cannot be null");
        }

        if (Objects.isNull(message)) {
            throw new IllegalStateException("message cannot be null");
        }

        if (Objects.isNull(signature)) {
            throw new IllegalStateException("signature cannot be null");
        }

        if (publicKeys.isEmpty()) {
            return false;
        }

        return verify(aggregatePublicKeys(publicKeys), message, signature);
    }

    private static class HOLDER {
        private static final ProofOfPossessionSignatureScheme INSTANCE = new ProofOfPossessionSignatureScheme();
    }

}
