package surf.superhighway.bls;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static surf.superhighway.bls.TestBytes.hex;
import static surf.superhighway.bls.TestBytes.of;

/**
 * Key derivation against Chia's vectors: EIP-2333 cases from bls-signatures and values generated
 * with Chia's Python reference implementation (python-impl). chia-bls (Rust) vectors are in the
 * Rust*Test classes.
 */
class HDKeysTest {

    private static final String RUST_TEST_SK = "52d75c4707e39595b27314547f9723e5530c01198af3fc5849d9a7af65631efb";

    @ParameterizedTest
    @CsvSource({
            "3141592653589793238462643383279502884197169399375105820974944592, 4ff5e145590ed7b71e577bb04032396d1619ff41cb4e350053ed2dce8d1efd1c, 5c62dcf9654481292aafa3348f1d1b0017bbfb44d6881d26d2b17836b38f204d, 3141592653",
            "0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00, 1ebd704b86732c3f05f30563dee6189838e73998ebc9c209ccff422adee10c4b, 1b98db8b24296038eae3f64c25d693a269ef1e4d7ae0f691c572a46cf3c0913c, 4294967295",
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3, 614d21b10c0e4996ac0608e0e7452d5720d95d20fe03c59a3321000a42432e1a, 08de7136e4afc56ae3ec03b20517d9c1232705a747f588fd17832f36ae337526, 42",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04, 0befcabff4a664461cc8f190cdd51c05621eb2837c71a1362df5b465a674ecfb, 1a1de3346883401f1e3b2281be5774080edb8e5ebe6f776b0f7af9fea942553a, 0",
    })
    void eip2333HardenedVectors(String seed, String master, String child, long index) {
        PrivateKey masterKey = PrivateKey.fromSeed(hex(seed));
        assertEquals(master, hex(masterKey.toBytes()));
        assertEquals(child, hex(masterKey.deriveHardened(index).toBytes()));
        assertEquals(master, hex(masterKey.toBytes()), "parent must not change");
    }

    @Test
    void maximumIndexIsSupported() {
        // Generated with python-impl: derive_child_g1_unhardened(pk, 0xFFFFFFFF)
        PrivateKey sk = PrivateKey.fromBytes(hex(RUST_TEST_SK));
        PublicKey child = sk.getPublicKey().deriveUnhardened(0xFFFFFFFFL);
        assertEquals("b8b397a9bf38bcf6106f1c555aba0f799d1a37549e8893b8416c5315c561688d3c8a3a8a4aa3287af9b40b3b01187de2", hex(child.toBytes()));
        assertEquals(child, sk.deriveUnhardened(4294967295L).getPublicKey());
    }

    @ParameterizedTest
    @CsvSource({
            "0, 90b09b8486409d94653d21f0eb72be49724f4d80a30934b48decfce77c5867c553d73ba3795f9d9b2c5262d3b8ca049912a412e9c1b0a1eb9d0256b9c8d768086dfb4381b0fde09bd1ed3ec2da84e9c3d060c436718e27637cf5ee93f28f5732",
            "1, 804d8297a93c4479744a91d47f3b23249226f87e41b730d816381db30edffdeeb62b82cc5c23c55d39c56346165a6b4716e3ba0d2cc6405cd07f3f634013a7026b8db201f3ce3f4ec5c944329e510a3f8e0f0b88b0991fcbafe5e980830b27b2",
            "4294967295, 8e5c95e7b9f3ebec0f234c9e5c5f8555cb0070167a35d4e4aaaead1f7fe795874f681b8aaa171c30bc53683f49ee0e44036b6f3180fe77ce88537032ac1acaf36e832736536363d7616e8ef9bb598cb71cf951dcb4719d257bfeb97a80664a9b",
    })
    void signatureUnhardenedDerivationMatchesChiaReference(long index, String child) {
        // python-impl: sig + PrivateKey.from_bytes(SHA256(sig || index)).value * G2Generator()
        PrivateKey sk = PrivateKey.fromBytes(hex(RUST_TEST_SK));
        Signature signature = MessageAugmentationSignatureScheme.getInstance().sign(sk, of(1, 2, 3));
        assertEquals("924c956ff652c5471e1a45d1639459c9efac8369809f5cf2f098f253d672b4733ac1f7b82fa5a59c386c49fd2336280b0ecbcc4b04c4f67d53cc77f8bc0f18efdf9e1300213d950ac0dddd08828636b96f8162e2ec847540c2e88e0060ddfd45", hex(signature.toBytes()));
        assertEquals(child, hex(signature.deriveUnhardened(index).toBytes()));
    }

    @Test
    void walletPathsMatchChiaReference() {
        // python-impl: derive_child_sk[_unhardened] along m/12381/8444/2/5
        PrivateKey master = PrivateKey.fromBytes(hex(RUST_TEST_SK));
        assertEquals("5bc0dfd6b55a2a9acb3747452e0dbec74a6ba5030a2cec3c9d3be13c1081ce30",
                hex(HDKeys.masterToWalletUnhardened(master, 5).toBytes()));
        assertEquals("6bdc7a1e89b2db1928adc59f1cd54090c4898caf65c505902575f247204dc469",
                hex(HDKeys.masterToWalletHardened(master, 5).toBytes()));
        assertEquals(HDKeys.masterToWalletUnhardened(master, 5).getPublicKey(),
                HDKeys.masterToWalletUnhardened(master.getPublicKey(), 5));
        assertEquals(HDKeys.masterToWalletUnhardened(master, 5),
                HDKeys.masterToWalletUnhardenedIntermediate(master).deriveUnhardened(5));
    }

    @Test
    void privateAndPublicUnhardenedDerivationAgreeAcrossGenerations() {
        PrivateKey sk = PrivateKey.fromSeed(of(1, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29));
        PrivateKey child = sk.deriveUnhardened(42);
        PublicKey childPk = sk.getPublicKey().deriveUnhardened(42);
        assertEquals(child.getPublicKey(), childPk);
        assertEquals(child.deriveUnhardened(12142).getPublicKey(), childPk.deriveUnhardened(12142));

        PrivateKey hardened = sk.deriveHardened(42);
        assertNotEquals(hardened, child);
        assertNotEquals(hardened.getPublicKey(), childPk);
        assertNotEquals(hardened, sk);
    }

    @Test
    void poolAuthenticationIndexIsBounded() {
        PrivateKey master = PrivateKey.fromBytes(hex(RUST_TEST_SK));
        assertThrows(IllegalArgumentException.class, () -> HDKeys.masterToPoolAuthentication(master, 10000, 0));
        assertThrows(IllegalArgumentException.class, () -> HDKeys.masterToPoolAuthentication(master, 0, -1));
    }
}
