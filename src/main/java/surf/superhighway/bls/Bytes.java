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

    static final long MAX_INDEX = 0xFFFF_FFFFL;

    /**
     * Validates a child index (a Rust {@code u32}) and returns its 32 bits as an int.
     *
     * @throws IllegalArgumentException if {@code index} is outside [0, 4294967295]
     */
    static int childIndex(long index) {
        if (index < 0 || index > MAX_INDEX) {
            throw new IllegalArgumentException("Child index must be in [0, 4294967295] (u32), got " + index);
        }
        return (int) index;
    }

    /** I2OSP(index, 4): a validated child index as 4 big-endian bytes, as Rust's {@code u32::to_be_bytes}. */
    static byte[] uint32(long index) {
        int value = childIndex(index);
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
