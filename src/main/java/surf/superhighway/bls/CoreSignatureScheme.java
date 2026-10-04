package surf.superhighway.bls;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * Shared implementation of the three schemes (Chia's {@code CoreMPL}). Subclasses customise
 * behaviour through {@link #augment} and {@link #acceptsMessages}.
 */
public abstract sealed class CoreSignatureScheme implements SignatureScheme
        permits BasicSignatureScheme, MessageAugmentationSignatureScheme, ProofOfPossessionSignatureScheme {

    private final CipherSuiteID cipherSuiteID;
    private final byte[] dst;

    CoreSignatureScheme(CipherSuiteID cipherSuiteID) {
        this.cipherSuiteID = cipherSuiteID;
        this.dst = cipherSuiteID.getStringValue().getBytes(StandardCharsets.US_ASCII);
    }

    public CipherSuiteID getCipherSuiteID() {
        return cipherSuiteID;
    }

    /** The message actually hashed for {@code publicKey}; the augmentation scheme prepends the key. */
    byte[] augment(PublicKey publicKey, byte[] message) {
        return message;
    }

    /** Scheme-specific precondition on aggregate messages; the basic scheme requires distinct ones. */
    boolean acceptsMessages(List<byte[]> messages) {
        return true;
    }

    @Override
    public PublicKey privateKeyToPublicKey(PrivateKey privateKey) {
        return Objects.requireNonNull(privateKey, "privateKey").getPublicKey();
    }

    @Override
    public Signature sign(PrivateKey privateKey, byte[] message) {
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(message, "message");
        return privateKey.sign(augment(privateKey.getPublicKey(), message), dst);
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] message, Signature signature) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(signature, "signature");
        return coreVerify(publicKey, augment(publicKey, message), signature, dst);
    }

    @Override
    public Signature aggregateSignatures(List<Signature> signatures) {
        return Signature.aggregate(signatures);
    }

    @Override
    public PublicKey aggregatePublicKeys(List<PublicKey> publicKeys) {
        return PublicKey.aggregate(publicKeys);
    }

    @Override
    public boolean aggregateVerify(List<PublicKey> publicKeys, List<byte[]> messages, Signature signature) {
        Objects.requireNonNull(publicKeys, "publicKeys");
        Objects.requireNonNull(messages, "messages");
        Objects.requireNonNull(signature, "signature");
        if (publicKeys.size() != messages.size()) {
            throw new IllegalArgumentException("The number of public keys must match the number of messages");
        }
        for (int i = 0; i < publicKeys.size(); i++) {
            Objects.requireNonNull(publicKeys.get(i), "publicKeys contains null");
            Objects.requireNonNull(messages.get(i), "messages contains null");
        }
        if (!acceptsMessages(messages)) {
            return false;
        }

        // Mirrors chia-bls aggregate_verify: the signature and every key must be valid group elements.
        if (!signature.isValid()) {
            return false;
        }
        if (publicKeys.isEmpty()) {
            return signature.isInfinity();
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment tag = arena.allocateFrom(JAVA_BYTE, dst);   // must outlive the context
            MemorySegment context = arena.allocate(Blst.PAIRING_SIZE, Blst.ALIGNMENT);
            Blst.pairingInit(context, tag, dst.length);

            for (int i = 0; i < publicKeys.size(); i++) {
                PublicKey publicKey = publicKeys.get(i);
                if (!publicKey.isValid()) {
                    return false;
                }
                byte[] message = augment(publicKey, messages.get(i));
                int error = Blst.pairingAggregatePkInG1(context, publicKey.toAffine(arena),
                        nativeBytes(arena, message), message.length);
                if (error != Blst.BLST_SUCCESS) {
                    return false;
                }
            }

            Blst.pairingCommit(context);
            MemorySegment signatureGt = arena.allocate(Blst.FP12_SIZE, Blst.ALIGNMENT);
            Blst.aggregatedInG2(signatureGt, signature.toAffine(arena));
            return Blst.pairingFinalVerify(context, signatureGt);
        }
    }

    /**
     * Single-signature verification. blst checks that both points lie in their subgroups and
     * rejects an infinite public key.
     */
    static boolean coreVerify(PublicKey publicKey, byte[] message, Signature signature, byte[] dst) {
        try (Arena arena = Arena.ofConfined()) {
            int error = Blst.coreVerifyPkInG1(publicKey.toAffine(arena), signature.toAffine(arena),
                    nativeBytes(arena, message), message.length, arena.allocateFrom(JAVA_BYTE, dst), dst.length);
            return error == Blst.BLST_SUCCESS;
        }
    }

    byte[] dst() {
        return dst;
    }

    private static MemorySegment nativeBytes(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1));
        MemorySegment.copy(bytes, 0, segment, JAVA_BYTE, 0, bytes.length);
        return segment;
    }
}
