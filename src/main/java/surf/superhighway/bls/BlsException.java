package surf.superhighway.bls;

/**
 * Invalid key or signature data. {@link #getKind()} and the message mirror chia-bls's
 * {@code Error} enum, so callers can branch on the same cases as Rust code.
 */
public final class BlsException extends IllegalArgumentException {

    public enum Kind {
        /** chia-bls {@code Error::SecretKeyGroupOrder}. */
        SECRET_KEY_GROUP_ORDER,
        /** chia-bls {@code Error::G1NotCanonical}. */
        G1_NOT_CANONICAL,
        /** chia-bls {@code Error::G1InfinityInvalidBits}. */
        G1_INFINITY_INVALID_BITS,
        /** chia-bls {@code Error::G1InfinityNotZero}. */
        G1_INFINITY_NOT_ZERO,
        /** chia-bls {@code Error::InvalidPublicKey(BLST_ERROR)}. */
        INVALID_PUBLIC_KEY,
        /** chia-bls {@code Error::InvalidSignature(BLST_ERROR)}. */
        INVALID_SIGNATURE
    }

    private static final long serialVersionUID = 1L;

    private final Kind kind;
    private final BlstError blstError;

    private BlsException(Kind kind, BlstError blstError, String message) {
        super(message);
        this.kind = kind;
        this.blstError = blstError;
    }

    static BlsException of(Kind kind) {
        return switch (kind) {
            case SECRET_KEY_GROUP_ORDER -> new BlsException(kind, null, "SecretKey byte data must be less than the group order");
            case G1_NOT_CANONICAL -> new BlsException(kind, null, "Given G1 infinity element must be canonical");
            case G1_INFINITY_INVALID_BITS -> new BlsException(kind, null, "Given G1 non-infinity element must start with 0b10");
            case G1_INFINITY_NOT_ZERO -> new BlsException(kind, null, "G1 non-infinity element can't have only zeros");
            case INVALID_PUBLIC_KEY, INVALID_SIGNATURE -> throw new IllegalArgumentException(kind + " needs a BLST error");
        };
    }

    static BlsException invalidPublicKey(BlstError error) {
        return new BlsException(Kind.INVALID_PUBLIC_KEY, error, "PublicKey is invalid (BLST ERROR: " + error + ")");
    }

    static BlsException invalidSignature(BlstError error) {
        return new BlsException(Kind.INVALID_SIGNATURE, error, "Signature is invalid (BLST ERROR: " + error + ")");
    }

    public Kind getKind() {
        return kind;
    }

    /** The blst error for {@link Kind#INVALID_PUBLIC_KEY} and {@link Kind#INVALID_SIGNATURE}; otherwise null. */
    public BlstError getBlstError() {
        return blstError;
    }
}
