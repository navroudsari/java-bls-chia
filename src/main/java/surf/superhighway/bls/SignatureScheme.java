package surf.superhighway.bls;

import java.util.List;

/**
 * A BLS signature scheme from draft-irtf-cfrg-bls-signature, minimal-pubkey-size variant,
 * as implemented by Chia: {@link BasicSignatureScheme}, {@link MessageAugmentationSignatureScheme}
 * and {@link ProofOfPossessionSignatureScheme}.
 *
 * <p>All methods throw {@link NullPointerException} for null arguments or list elements.
 * Verification methods return {@code false}, rather than throwing, for any key or signature
 * that is not a valid group element.
 */
public interface SignatureScheme {

    /** Same as {@link PrivateKey#getPublicKey()}. */
    PublicKey privateKeyToPublicKey(PrivateKey privateKey);

    Signature sign(PrivateKey privateKey, byte[] message);

    boolean verify(PublicKey publicKey, byte[] message, Signature signature);

    /** Sums signatures; an empty list yields {@link Signature#infinity()}. */
    Signature aggregateSignatures(List<Signature> signatures);

    /** Sums public keys; an empty list yields {@link PublicKey#infinity()}. */
    PublicKey aggregatePublicKeys(List<PublicKey> publicKeys);

    /**
     * Verifies an aggregate signature over {@code messages[i]} signed by {@code publicKeys[i]}.
     * With no keys and messages, returns true only for the infinity signature.
     *
     * @throws IllegalArgumentException if the lists differ in size
     */
    boolean aggregateVerify(List<PublicKey> publicKeys, List<byte[]> messages, Signature signature);
}
