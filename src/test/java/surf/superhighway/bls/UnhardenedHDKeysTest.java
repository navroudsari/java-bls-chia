package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt32;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class UnhardenedHDKeysTest {

    @Test
    public void ShouldMatchDerivationThroughPrivateAndPublicKeysTest() {
        BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();
        Bytes seed = Bytes.of(1, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29);

        PrivateKey privateKey = BasicSignatureScheme.keygen(seed);
        PublicKey publicKey = privateKey.getPublicKey();

        PrivateKey childPrivateKey = basicSchemeMPL.deriveChildPrivateKeyUnhardened(privateKey, UInt32.valueOf(42));
        PublicKey childPublicKey = basicSchemeMPL.deriveChildPublicKeyUnhardened(publicKey, UInt32.valueOf(42));

        assertEquals(childPrivateKey.getPublicKey(), childPublicKey);

        PrivateKey grandchildPrivateKey = basicSchemeMPL.deriveChildPrivateKeyUnhardened(childPrivateKey, UInt32.valueOf(12142));
        PublicKey grandchildPublicKey = basicSchemeMPL.deriveChildPublicKeyUnhardened(childPublicKey, UInt32.valueOf(12142));

        assertEquals(grandchildPrivateKey.getPublicKey(), grandchildPublicKey);
    }

    @Test
    public void shouldDerivePublicChildFromParentTest() {
        BasicSignatureScheme basicSchemeMPL = BasicSignatureScheme.getInstance();

        Bytes seed = Bytes.of(2, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29);

        PrivateKey privateKey = BasicSignatureScheme.keygen(seed);
        PublicKey publicKey = privateKey.getPublicKey();
        PrivateKey childSecretKey = basicSchemeMPL.deriveChildPrivateKeyUnhardened(privateKey, UInt32.valueOf(42));
        PublicKey childPublicKey = basicSchemeMPL.deriveChildPublicKeyUnhardened(publicKey, UInt32.valueOf(42));

        PrivateKey childSecretKeyHardened = basicSchemeMPL.deriveChildPrivateKey(privateKey, UInt32.valueOf(42));

        assertEquals(childSecretKey.getPublicKey(), childPublicKey);
        assertNotEquals(childSecretKeyHardened, childSecretKey);
        assertNotEquals(childSecretKeyHardened.getPublicKey(), childPublicKey);
    }
}