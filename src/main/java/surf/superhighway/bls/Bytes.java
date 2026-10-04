package surf.superhighway.bls;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/** Byte helpers. Only used for public data; secrets never pass through here. */
final class Bytes {

    private Bytes() {
    }

    static byte[] sha256(byte[]... parts) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
        for (byte[] part : parts) {
            digest.update(part);
        }
        return digest.digest();
    }

    /** I2OSP(value, 4): the index as 4 big-endian bytes, treating {@code value} as unsigned. */
    static byte[] uint32(int value) {
        return new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static void requireLength(byte[] bytes, int length, String what) {
        Objects.requireNonNull(bytes, what);
        if (bytes.length != length) {
            throw new IllegalArgumentException(what + " must be " + length + " bytes, got " + bytes.length);
        }
    }

    static boolean allZero(byte[] bytes, int from) {
        int acc = 0;
        for (int i = from; i < bytes.length; i++) {
            acc |= bytes[i];
        }
        return acc == 0;
    }
}
