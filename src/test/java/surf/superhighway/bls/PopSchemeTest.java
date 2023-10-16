package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PopSchemeTest {

    @Test
    public void popScheme() {
        Bytes seed1 = Bytes32.repeat((byte) 0x06);
        Bytes seed2 = Bytes32.repeat((byte) 0x07);
        Bytes message1 = Bytes.of(7, 8, 9);
        Bytes message2 = Bytes.of(10, 11, 12);
        List<Bytes> messages = List.of(message1, message2);


        ProofOfPossessionSignatureScheme popSchemeMPL = ProofOfPossessionSignatureScheme.getInstance();
        PrivateKey privateKey1 = ProofOfPossessionSignatureScheme.keygen(seed1);
        PublicKey publicKey1 = popSchemeMPL.privateKeyToPublicKey(privateKey1);
        Signature signature1 = popSchemeMPL.sign(privateKey1, message1);

        assertTrue(popSchemeMPL.verify(publicKey1, message1, signature1));

        PrivateKey privateKey2 = ProofOfPossessionSignatureScheme.keygen(seed2);
        PublicKey publicKey2 = popSchemeMPL.privateKeyToPublicKey(privateKey2);
        Signature signature2 = popSchemeMPL.sign(privateKey2, message2);

        // Wrong Signature
        assertFalse(popSchemeMPL.verify(publicKey1, message1, signature2));
        // Wrong message
        assertFalse(popSchemeMPL.verify(publicKey1, message2, signature1));
        // Wrong pk
        assertFalse(popSchemeMPL.verify(publicKey2, message1, signature1));

        Signature aggregatedSignature = popSchemeMPL.aggregateSignatures(List.of(signature1, signature2));
        assertTrue(popSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2), messages, aggregatedSignature));

        // PopVerify
        Signature proof1 = popSchemeMPL.popProve(privateKey1);
        assertTrue(popSchemeMPL.popVerify(publicKey1, proof1));

        // FastAggregateVerify
        // We want privateKey2 to sign the same message
        Signature sameSignature2 = popSchemeMPL.sign(privateKey2, message1);
        Signature sameAggregatedSignature = popSchemeMPL.aggregateSignatures(List.of(signature1, sameSignature2));
        assertTrue(popSchemeMPL.fastAggregateVerify(List.of(publicKey1, publicKey2), message1, sameAggregatedSignature));
    }
}
