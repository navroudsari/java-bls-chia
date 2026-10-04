package surf.superhighway.bls;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

final class TestBytes {

    private static final SecureRandom RANDOM = new SecureRandom();

    private TestBytes() {
    }

    /** Bytes from int literals, e.g. {@code of(1, 2, 254)}. */
    static byte[] of(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }

    static byte[] repeat(int value, int length) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }

    static byte[] hex(String hex) {
        return HexFormat.of().parseHex(hex.startsWith("0x") ? hex.substring(2) : hex);
    }

    static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    static byte[] random(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }
}
