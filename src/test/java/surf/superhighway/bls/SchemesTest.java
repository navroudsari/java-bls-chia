package surf.superhighway.bls;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.of;
import static surf.superhighway.bls.TestBytes.repeat;

/** Sign/verify round trips for each scheme (ported from BasicSchemeTest, AugSchemeTest, PopSchemeTest). */
class SchemesTest {

    private static void assertSchemeBehaviour(SignatureScheme scheme) {
        byte[] message1 = of(7, 8, 9);
        byte[] message2 = of(10, 11, 12);

        PrivateKey privateKey1 = PrivateKey.fromSeed(repeat(0x04, 32));
        PublicKey publicKey1 = scheme.privateKeyToPublicKey(privateKey1);
        Signature signature1 = scheme.sign(privateKey1, message1);
        assertTrue(scheme.verify(publicKey1, message1, signature1));

        PrivateKey privateKey2 = PrivateKey.fromSeed(repeat(0x05, 32));
        PublicKey publicKey2 = scheme.privateKeyToPublicKey(privateKey2);
        Signature signature2 = scheme.sign(privateKey2, message2);

        assertFalse(scheme.verify(publicKey1, message1, signature2), "wrong signature");
        assertFalse(scheme.verify(publicKey1, message2, signature1), "wrong message");
        assertFalse(scheme.verify(publicKey2, message1, signature1), "wrong public key");

        Signature aggregate = scheme.aggregateSignatures(List.of(signature1, signature2));
        assertTrue(scheme.aggregateVerify(List.of(publicKey1, publicKey2), List.of(message1, message2), aggregate));
    }

    @Test
    void basicScheme() {
        assertSchemeBehaviour(BasicSignatureScheme.getInstance());
    }

    @Test
    void augScheme() {
        assertSchemeBehaviour(MessageAugmentationSignatureScheme.getInstance());
    }

    @Test
    void popScheme() {
        ProofOfPossessionSignatureScheme pop = ProofOfPossessionSignatureScheme.getInstance();
        assertSchemeBehaviour(pop);

        byte[] message1 = of(7, 8, 9);
        PrivateKey privateKey1 = PrivateKey.fromSeed(repeat(0x06, 32));
        PrivateKey privateKey2 = PrivateKey.fromSeed(repeat(0x07, 32));
        PublicKey publicKey1 = privateKey1.getPublicKey();
        PublicKey publicKey2 = privateKey2.getPublicKey();

        Signature proof1 = pop.popProve(privateKey1);
        assertTrue(pop.popVerify(publicKey1, proof1));
        assertFalse(pop.popVerify(publicKey2, proof1));

        // Same message signed by both keys
        Signature aggregate = pop.aggregateSignatures(List.of(pop.sign(privateKey1, message1), pop.sign(privateKey2, message1)));
        assertTrue(pop.fastAggregateVerify(List.of(publicKey1, publicKey2), message1, aggregate));
    }
}
