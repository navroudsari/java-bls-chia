package surf.superhighway.bls;

/** blst's {@code BLST_ERROR} codes, as reported in {@link BlsException}. */
public enum BlstError {
    BLST_SUCCESS,
    BLST_BAD_ENCODING,
    BLST_POINT_NOT_ON_CURVE,
    BLST_POINT_NOT_IN_GROUP,
    BLST_AGGR_TYPE_MISMATCH,
    BLST_VERIFY_FAIL,
    BLST_PK_IS_INFINITY,
    BLST_BAD_SCALAR;

    static BlstError fromCode(int code) {
        BlstError[] values = values();
        if (code < 0 || code >= values.length) {
            throw new IllegalStateException("Unknown BLST_ERROR code " + code);
        }
        return values[code];
    }
}
