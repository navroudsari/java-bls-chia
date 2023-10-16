package surf.superhighway.bls;

/**
 * Enum representing different cipher schemes.
 */
@SuppressWarnings("SpellCheckingInspection")
public enum CipherSuiteID {
    /**
     * Basic scheme for minimal-pubkey-size.
     */
    BLS_SIG_BASIC_SCHEME_MPL("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"),
    /**
     * Basic scheme for minimal-pubkey-size.
     */
    BLS_SIG_AUG_SCHEME_MPL("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"),
    /**
     * Proof of Possession scheme for minimal-pubkey-size (hash to point).
     */
    BLS_SIG_POP_SCHEME_MPL("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"),
    /**
     * Proof of Possession scheme for minimal-pubkey-size (hash pubkey to point).
     */
    BLS_POP_SCHEME_MPL("BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");

    private final String stringValue;

    CipherSuiteID(final String stringValue) {
        this.stringValue = stringValue;
    }

    public String getStringValue() {
        return stringValue;
    }
}
