package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class BasicSignatureScheme extends CoreSignatureScheme {
    private BasicSignatureScheme() {
        super(CipherSuiteID.BLS_SIG_BASIC_SCHEME_MPL);
    }

    public static BasicSignatureScheme getInstance() {
        return BasicSignatureScheme.Holder.INSTANCE;
    }

    /**
     * Verify BLS signature against their corresponding messages and public keys.
     * This first makes sure all messages are unique before invoking the core aggregate vrify function.
     *
     * @param publicKeys A list of public keys corresponding to the signers of the messages.
     * @param messages   A list of messages that were signed. The order of messages should match the order of public keys.
     * @param signature  The aggregated signature that corresponds to the aggregated public keys and messages.
     * @return Returns true if the aggregated signature verification is successful; false otherwise.
     * @throws IllegalArgumentException If the size of the public keys list does not match the size of the messages list or if any of the arguments is null.
     */
    @Override
    public boolean aggregateVerify(final List<PublicKey> publicKeys, final List<Bytes> messages, final Signature signature) {
        if (Objects.isNull(publicKeys)) {
            throw new IllegalArgumentException("publicKey list cannot be null");
        }

        if (Objects.isNull(messages)) {
            throw new IllegalArgumentException("message list cannot be null");
        }

        if (Objects.isNull(signature)) {
            throw new IllegalArgumentException("signature cannot be null");
        }

        if (publicKeys.size() != messages.size()) {
            throw new IllegalArgumentException("The number of public keys must match the number of messages");
        }

        InvariantResult argCheck = verifyAggregateSignatureArguments(publicKeys.size(), messages.size(), signature);
        if (argCheck != InvariantResult.CONTINUE) {
            return argCheck == InvariantResult.GOOD;
        }


        final Set<Bytes> uniqueMessages = new HashSet<>(messages);
        if (uniqueMessages.size() != messages.size()) {
            return false;
        }

        return super.aggregateVerify(publicKeys, messages, signature);
    }

    private static class Holder {
        private static final BasicSignatureScheme INSTANCE = new BasicSignatureScheme();
    }
}
