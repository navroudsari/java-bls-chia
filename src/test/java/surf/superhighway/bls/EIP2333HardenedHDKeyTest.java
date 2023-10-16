package surf.superhighway.bls;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt32;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class EIP2333HardenedHDKeyTest {

    public void testEIP2333(String seedHex, String masterPrivateKeyHex, String childPrivateKeyHex, UInt32 childIndex) {
        Bytes masterSk = Bytes.fromHexString(masterPrivateKeyHex);
        Bytes childSk = Bytes.fromHexString(childPrivateKeyHex);

        PrivateKey master = BasicSignatureScheme.keygen(Bytes.fromHexString(seedHex));
        assertEquals(masterSk, master.serialize());

        PrivateKey child = HDKeys.deriveChildSk(master, childIndex);

        Bytes calculatedMaster = master.serialize();
        Bytes calculatedChild = child.serialize();

        assertEquals(masterSk, calculatedMaster);
        assertEquals(childSk, calculatedChild);
    }

    @Test
    public void testCase1() {
        //noinspection SpellCheckingInspection
        testEIP2333("0x3141592653589793238462643383279502884197169399375105820974944592", "0x4ff5e145590ed7b71e577bb04032396d1619ff41cb4e350053ed2dce8d1efd1c", "0x5c62dcf9654481292aafa3348f1d1b0017bbfb44d6881d26d2b17836b38f204d", UInt32.valueOf(BigInteger.valueOf(3141592653L)));
    }

    @Test
    public void testCase2() {
        //noinspection SpellCheckingInspection
        testEIP2333("0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00", "0x1ebd704b86732c3f05f30563dee6189838e73998ebc9c209ccff422adee10c4b", "0x1b98db8b24296038eae3f64c25d693a269ef1e4d7ae0f691c572a46cf3c0913c", UInt32.valueOf(BigInteger.valueOf(4294967295L)));
    }

    @Test
    public void testCase3() {
        testEIP2333("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "0x614d21b10c0e4996ac0608e0e7452d5720d95d20fe03c59a3321000a42432e1a", "0x08de7136e4afc56ae3ec03b20517d9c1232705a747f588fd17832f36ae337526", UInt32.valueOf(BigInteger.valueOf(42)));
    }

    @Test
    public void testCase4() {
        //noinspection SpellCheckingInspection
        testEIP2333("0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", "0x0befcabff4a664461cc8f190cdd51c05621eb2837c71a1362df5b465a674ecfb", "0x1a1de3346883401f1e3b2281be5774080edb8e5ebe6f776b0f7af9fea942553a", UInt32.valueOf(BigInteger.valueOf(0)));
    }


}
