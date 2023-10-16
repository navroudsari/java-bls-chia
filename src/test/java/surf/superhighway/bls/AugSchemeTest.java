package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AugSchemeTest {

    @Test
    public void augSchemeTest() {
        Bytes seed1 = Bytes32.repeat((byte) 0x04);
        Bytes seed2 = Bytes32.repeat((byte) 0x05);
        Bytes message1 = Bytes.of(7, 8, 9);
        Bytes message2 = Bytes.of(10, 11, 12);
        List<Bytes> messages = List.of(message1, message2);

        MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();
        PrivateKey privateKey1 = MessageAugmentationSignatureScheme.keygen(seed1);
        PublicKey publicKey1 = augSchemeMPL.privateKeyToPublicKey(privateKey1);
        Signature signature1 = augSchemeMPL.sign(privateKey1, message1);

        assertTrue(augSchemeMPL.verify(publicKey1, message1, signature1));

        PrivateKey privateKey2 = MessageAugmentationSignatureScheme.keygen(seed2);
        PublicKey publicKey2 = augSchemeMPL.privateKeyToPublicKey(privateKey2);
        Signature signature2 = augSchemeMPL.sign(privateKey2, message2);

        // Wrong G2Element
        assertFalse(augSchemeMPL.verify(publicKey1, message1, signature2));

        // Wrong msg
        assertFalse(augSchemeMPL.verify(publicKey1, message2, signature1));

        // Wrong pk
        assertFalse(augSchemeMPL.verify(publicKey2, message1, signature1));

        Signature aggregatedSignature = augSchemeMPL.aggregateSignatures(List.of(signature1, signature2));
        assertTrue(augSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2), messages, aggregatedSignature));
    }
}
