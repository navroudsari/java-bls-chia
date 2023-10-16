package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.Bytes48;
import org.junit.Test;

import static org.junit.Assert.*;

public class PublicKeyTest {

    @Test
    public void InvalidPublicKeyTest() {
        String badPointHex = "0x8d5d0fb73b9c92df4eab4216e48c3e358578b4cc30f82c268bd6fef3bd34b558628daf1afef798d4c3b0fcd8b28c8973";

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> PublicKey.fromBytes(Bytes48.fromHexString(badPointHex)));
        assertEquals("PublicKey is invalid", exception.getMessage());

        PublicKey badPublicKey = PublicKey.fromBytesUnchecked(Bytes48.fromHexString(badPointHex));
        assertFalse(badPublicKey.isValid());

        Bytes seed = Bytes32.repeat((byte) 0x05);
        Bytes message = Bytes.of(10, 11, 12);
        PrivateKey privateKey = BasicSignatureScheme.keygen(seed);
        PublicKey goodPublicKey = BasicSignatureScheme.getInstance().privateKeyToPublicKey(privateKey);
        assertTrue(goodPublicKey.isValid());
        MessageAugmentationSignatureScheme augSchemeMPL = MessageAugmentationSignatureScheme.getInstance();
        Signature signature = augSchemeMPL.sign(privateKey, message);
        assertFalse(augSchemeMPL.verify(badPublicKey, message, signature));
        assertTrue(augSchemeMPL.verify(goodPublicKey, message, signature));
    }
}
