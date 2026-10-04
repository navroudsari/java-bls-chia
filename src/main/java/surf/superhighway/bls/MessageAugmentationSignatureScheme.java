package surf.superhighway.bls;

import java.util.Objects;

/**
 * The message augmentation scheme (Chia's {@code AugSchemeMPL}, and the only scheme in chia-bls):
 * every message is prefixed with the signer's serialized public key before hashing.
 */
public final class MessageAugmentationSignatureScheme extends CoreSignatureScheme {

    private static final MessageAugmentationSignatureScheme INSTANCE = new MessageAugmentationSignatureScheme();

    private MessageAugmentationSignatureScheme() {
        super(CipherSuiteID.BLS_SIG_AUG_SCHEME_MPL);
    }

    public static MessageAugmentationSignatureScheme getInstance() {
        return INSTANCE;
    }

    @Override
    byte[] augment(PublicKey publicKey, byte[] message) {
        return Bytes.concat(publicKey.bytesUnsafe(), message);
    }

    /**
     * Signs {@code message} prefixed with {@code prependPublicKey} instead of the signer's own key,
     * as chia-bls {@code SecretKey::sign(msg, final_pk)} does. Used when several signers sign the
     * same message for one aggregate public key.
     */
    public Signature sign(PrivateKey privateKey, byte[] message, PublicKey prependPublicKey) {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(prependPublicKey, "prependPublicKey");
        return privateKey.sign(augment(prependPublicKey, message), dst());
    }
}
