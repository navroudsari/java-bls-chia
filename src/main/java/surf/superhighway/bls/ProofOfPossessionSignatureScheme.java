package surf.superhighway.bls;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

/**
 * The proof-of-possession scheme (Chia's {@code PopSchemeMPL}). Each public key must be
 * accompanied by a proof of possession checked with {@link #popVerify}; keys that have passed it
 * can sign the same message and be verified together with {@link #fastAggregateVerify}.
 */
public final class ProofOfPossessionSignatureScheme extends CoreSignatureScheme {

    private static final ProofOfPossessionSignatureScheme INSTANCE = new ProofOfPossessionSignatureScheme();
    private static final byte[] POP_DST = CipherSuiteID.BLS_POP_SCHEME_MPL.getStringValue().getBytes(StandardCharsets.US_ASCII);

    private ProofOfPossessionSignatureScheme() {
        super(CipherSuiteID.BLS_SIG_POP_SCHEME_MPL);
    }

    public static ProofOfPossessionSignatureScheme getInstance() {
        return INSTANCE;
    }

    /** Signs the serialized public key under the proof-of-possession tag. */
    public Signature popProve(PrivateKey privateKey) {
        Objects.requireNonNull(privateKey, "privateKey");
        return privateKey.sign(privateKey.getPublicKey().bytesUnsafe(), POP_DST);
    }

    public boolean popVerify(PublicKey publicKey, Signature proof) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(proof, "proof");
        return coreVerify(publicKey, publicKey.bytesUnsafe(), proof, POP_DST);
    }

    /**
     * Verifies a signature on one message by all {@code publicKeys}, each of which must already
     * have passed {@link #popVerify}. Returns false for an empty list or any invalid key.
     */
    public boolean fastAggregateVerify(List<PublicKey> publicKeys, byte[] message, Signature signature) {
        Objects.requireNonNull(publicKeys, "publicKeys");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(signature, "signature");
        if (publicKeys.isEmpty()) {
            return false;
        }
        for (PublicKey publicKey : publicKeys) {
            // Off-subgroup keys could cancel out in the sum and pass the aggregate's group check.
            if (!Objects.requireNonNull(publicKey, "publicKeys contains null").isValid()) {
                return false;
            }
        }
        return coreVerify(PublicKey.aggregate(publicKeys), message, signature, dst());
    }
}
