package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class MessageAugmentationSignatureScheme extends CoreSignatureScheme {

    private MessageAugmentationSignatureScheme() {
        super(CipherSuiteID.BLS_SIG_AUG_SCHEME_MPL);
    }

    public static MessageAugmentationSignatureScheme getInstance() {
        return Holder.INSTANCE;
    }

    /**
     * Signs the given message after concatenating the public key representation of the private key to the message.
     *
     * @param privateKey the private key used for signing.
     * @param message    the original message to be signed.
     * @return a {@link Signature} for the augmented message.
     * @throws IllegalArgumentException if any of the parameters are null.
     */
    @Override
    public Signature sign(final PrivateKey privateKey, final Bytes message) {

        if (Objects.isNull(privateKey)) {
            throw new IllegalArgumentException("privateKey cannot be null");
        }

        if (Objects.isNull(message)) {
            throw new IllegalArgumentException("message cannot be null");
        }

        // Augmenting the message with the public key
        final Bytes augmentedMessage = Bytes.concatenate(privateKey.getPublicKey().serialize(), message);
        return super.sign(privateKey, augmentedMessage);
    }

    /**
     * Signs the given message after concatenating the public key representation of the private key to the message.
     *
     * @param privateKey the private key used for signing.
     * @param message    the original message to be signed.
     * @param publicKey  the public key to be prepended to the message.
     * @return a {@link Signature} for the augmented message.
     * @throws IllegalArgumentException if any of the parameters are null.
     */
    public Signature sign(final PrivateKey privateKey, final Bytes message, final PublicKey publicKey) {

        if (Objects.isNull(privateKey)) {
            throw new IllegalArgumentException("privateKey cannot be null");
        }

        if (Objects.isNull(message)) {
            throw new IllegalArgumentException("message cannot be null");
        }

        if (Objects.isNull(publicKey)) {
            throw new IllegalArgumentException("publicKey cannot be null");
        }

        // Augmenting the message with the public key
        final Bytes augmentedMessage = Bytes.concatenate(publicKey.serialize(), message);
        return super.sign(privateKey, augmentedMessage);
    }


    /**
     * Verifies the signature for the given message after concatenating the serialized representation
     * of the public key to the original message.
     *
     * @param publicKey the public key used to verify the signature.
     * @param message   the original message whose signature is to be verified.
     * @param signature the signature to be verified against the augmented message.
     * @return true if the signature is valid for the augmented message; false otherwise.
     * @throws IllegalArgumentException if any of the parameters are null.
     */
    @Override
    public boolean verify(final PublicKey publicKey, final Bytes message, final Signature signature) {
        if (Objects.isNull(publicKey)) {
            throw new IllegalArgumentException("publicKey cannot be null");
        }

        if (Objects.isNull(message)) {
            throw new IllegalArgumentException("message cannot be null");
        }

        if (Objects.isNull(signature)) {
            throw new IllegalArgumentException("signature cannot be null");
        }

        final Bytes augmentedMessage = Bytes.concatenate(publicKey.serialize(), message);
        return super.verify(publicKey, augmentedMessage, signature);
    }

    /**
     * Verifies an aggregated signature for a list of messages after each message is
     * augmented with its corresponding serialized public key.
     *
     * @param publicKeys the list of public keys, each corresponding to a message.
     * @param messages   the original messages whose aggregated signature is to be verified.
     * @param signature  the aggregated signature to be verified against the augmented messages.
     * @return true if the aggregated signature is valid for the list of augmented messages; false otherwise.
     * @throws IllegalArgumentException if the provided lists are null, or if they have mismatched sizes.
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

        // Augmenting each message with its corresponding public key
        final List<Bytes> augmentedMessages = IntStream.range(0, publicKeys.size()).mapToObj(i -> Bytes.concatenate(publicKeys.get(i).serialize(), messages.get(i))).collect(Collectors.toList());

        return super.aggregateVerify(publicKeys, augmentedMessages, signature);
    }

    private static class Holder {
        private static final MessageAugmentationSignatureScheme INSTANCE = new MessageAugmentationSignatureScheme();
    }


}
