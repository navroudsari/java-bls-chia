package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes32;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

@SuppressWarnings("SpellCheckingInspection")
public class KeyGenTest {

    @Test
    public void testKeyGeneration() {
        Bytes32 seed = Bytes32.fromHexString("0x08");
        PrivateKey sk = BasicSignatureScheme.keygen(seed);
        assertEquals("0x672165263b758015ebcc5273993d1ba7d778910effc81f2a9acf7a482180a989", sk.serialize().toString());

        PublicKey pk = sk.getPublicKey();
        assertEquals("0x8effb4415cc6d10a2d4006f342da08035731e1ffef53ebf98e1ad1702ecde3e3706c818abbb15f49c227daec9eb0bc11", pk.serialize().toString());

        assertEquals("1371335225", pk.getFingerprintAsDecimalString());
        assertEquals("0x51bcea39", pk.getFingerprintAsHexString());
    }

    @Test
    public void testKeyGeneration2() {
        Bytes32 seed = Bytes32.repeat((byte) 8);
        PrivateKey sk = BasicSignatureScheme.keygen(seed);
        PublicKey pk = sk.getPublicKey();

        assertEquals("0x8ee7ba56", pk.getFingerprintAsHexString());
        assertEquals("2397551190", pk.getFingerprintAsDecimalString());
    }
}
