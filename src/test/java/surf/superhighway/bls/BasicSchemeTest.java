package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BasicSchemeTest {

    @Test
    public void basicSchemeTest() {
        Bytes seed1 = Bytes32.repeat((byte) 0x04);
        Bytes seed2 = Bytes32.repeat((byte) 0x05);
        Bytes message1 = Bytes.of(7, 8, 9);
        Bytes message2 = Bytes.of(10, 11, 12);
        List<Bytes> messages = List.of(message1, message2);

        BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();
        PrivateKey privateKey1 = BasicSignatureScheme.keygen(seed1);
        PublicKey publicKey1 = basicSchemeMPL.privateKeyToPublicKey(privateKey1);
        Signature signature1 = basicSchemeMPL.sign(privateKey1, message1);

        assertTrue(basicSchemeMPL.verify(publicKey1, message1, signature1));

        PrivateKey privateKey2 = BasicSignatureScheme.keygen(seed2);
        PublicKey publicKey2 = basicSchemeMPL.privateKeyToPublicKey(privateKey2);
        Signature signature2 = basicSchemeMPL.sign(privateKey2, message2);

        // Wrong Signature
        assertFalse(basicSchemeMPL.verify(publicKey1, message1, signature2));

        // Wrong msg
        assertFalse(basicSchemeMPL.verify(publicKey1, message2, signature1));

        // Wrong pk
        assertFalse(basicSchemeMPL.verify(publicKey2, message1, signature1));

        Signature aggregateSignature = basicSchemeMPL.aggregateSignatures(List.of(signature1, signature2));

        assertTrue(basicSchemeMPL.aggregateVerify(List.of(publicKey1, publicKey2), messages, aggregateSignature));
    }
}
