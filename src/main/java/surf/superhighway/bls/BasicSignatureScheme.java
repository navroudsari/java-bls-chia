package surf.superhighway.bls;

import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The basic scheme (Chia's {@code BasicSchemeMPL}). Aggregate verification requires all messages
 * to be distinct, which prevents rogue-key attacks.
 */
public final class BasicSignatureScheme extends CoreSignatureScheme {

    private static final BasicSignatureScheme INSTANCE = new BasicSignatureScheme();

    private BasicSignatureScheme() {
        super(CipherSuiteID.BLS_SIG_BASIC_SCHEME_MPL);
    }

    public static BasicSignatureScheme getInstance() {
        return INSTANCE;
    }

    @Override
    boolean acceptsMessages(List<byte[]> messages) {
        Set<ByteBuffer> unique = new HashSet<>();
        for (byte[] message : messages) {
            if (!unique.add(ByteBuffer.wrap(message))) {
                return false;
            }
        }
        return true;
    }
}
