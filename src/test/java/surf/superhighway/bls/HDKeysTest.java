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
 * Key derivation against Chia's vectors: EIP-2333 cases from bls-signatures, chia-bls (Rust)
 * unit tests, and values generated with Chia's Python reference implementation (python-impl).
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
        assertEquals(child, hex(masterKey.deriveHardened((int) index).toBytes()));
        assertEquals(master, hex(masterKey.toBytes()), "parent must not change");
    }

    @ParameterizedTest
    @CsvSource({
            "fc795be0c3f18c50dddb34e72179dc597d64055497ecc1e69e2e56a5409651bc139aae8070d4df0ea14d8d2a518a9a00bb1cc6e92e053fe34051f6821df9164c, 52d75c4707e39595b27314547f9723e5530c01198af3fc5849d9a7af65631efb",
            "b873212f885ccffbf4692afcb84bc2e55886de2dfa07d90f5c3c239abc31c0a6ce047e30fd8bf6a281e71389aa82d73df74c7bbfb3b06b4639a5cee775cccd3c, 35d65c35d926f62ba2dd128754ddb556edb4e2c926237ab9e02a23e7b3533613",
            "3e066d7dee2dbf8fcd3fe240a3975658ca118a8f6f4ca81cf99104944604b05a5090a79d99e545704b914ca0397fedb82fd00fd6a72098703709c891a065ee49, 59095c391107936599b7ee6f09067979b321932bd62e23c7f53ed5fb19f851f6",
    })
    void rustFromSeedVectors(String seed, String secretKey) {
        assertEquals(secretKey, hex(PrivateKey.fromSeed(hex(seed)).toBytes()));
    }

    @ParameterizedTest
    @CsvSource({
            "0, 05eccb2d70e814f51a30d8b9965505605c677afa97228fa2419db583a8121db9",
            "1, 612ae96bdce2e9bc01693ac579918fbb559e04ec365cce9b66bb80e328f62c46",
            "2, 5df14a0a34fd6c30a80136d4103f0a93422ce82d5c537bebbecbc56e19fee5b9",
            "3, 3ea55db88d9a6bf5f1d9c9de072e3c9a56b13f4156d72fca7880cd39b4bd4fdc",
    })
    void rustDeriveHardenedVectors(int index, String child) {
        PrivateKey sk = PrivateKey.fromBytes(hex(RUST_TEST_SK));
        assertEquals(child, hex(sk.deriveHardened(index).toBytes()));
    }

    @ParameterizedTest
    @CsvSource({
            "0, 399638f99d446500f3c3a363f24c2b0634ad7caf646f503455093f35f29290bd",
            "1, 3dcb4098ad925d8940e2f516d2d5a4dbab393db928a8c6cb06b93066a09a843a",
            "2, 13115c8fb68a3d667938dac2ffc6b867a4a0f216bbb228aa43d6bdde14245575",
            "3, 52e7e9f2fb51f2c5705aea8e11ac82737b95e664ae578f015af22031d956f92b",
    })
    void rustDeriveUnhardenedVectors(int index, String child) {
        PrivateKey sk = PrivateKey.fromBytes(hex(RUST_TEST_SK));
        PrivateKey derived = sk.deriveUnhardened(index);
        assertEquals(child, hex(derived.toBytes()));
        assertEquals(derived.getPublicKey(), sk.getPublicKey().deriveUnhardened(index));
    }

    @ParameterizedTest
    @CsvSource({
            "5aac8405befe4cb3748a67177c56df26355f1f98d979afdb0b2f97858d2f71c3, b9de000821a610ef644d160c810e35113742ff498002c2deccd8f1a349e423047e9b3fc17ebfc733dbee8fd902ba2961",
            "23f1fb291d3bd7434282578b842d5ea4785994bb89bd2c94896d1b4be6c70ba2, 96f304a5885e67abdeab5e1ed0576780a1368777ea7760124834529e8694a1837a20ffea107b9769c4f92a1f6c167e69",
            "2bc1d6d6efe58d365c29ccb7ad12c8457c0eec70a29003073692ac4cb1cd7ba2, b10568446def64b17fc9b6d614ae036deaac3f2d654e12e45ea04b19208246e0d760e8826426e97f9f0666b7ce340d75",
            "2bfc8672d859700e30aa6c8edc24a8ce9e6dc53bb1ef936f82de722847d05b9e, 9641472acbd6af7e5313d2500791b87117612af43eef929cf7975aaaa5a203a32698a8ef53763a84d90ad3f00b86ad66",
            "3311f883dad1e39c52bf82d5870d05371c0b1200576287b5160808f55568151b, 928ea102b5a3e3efe4f4c240d3458a568dfeb505e02901a85ed70a384944b0c08c703a35245322709921b8f2b7f5e54a",
    })
    void rustPublicKeyVectors(String secretKey, String publicKey) {
        assertEquals(PublicKey.fromBytes(hex(publicKey)), PrivateKey.fromBytes(hex(secretKey)).getPublicKey());
    }

    @Test
    void publicDerivationTreatsIndexAsUnsigned() {
        // Generated with python-impl: derive_child_g1_unhardened(pk, 0xFFFFFFFF)
        PrivateKey sk = PrivateKey.fromBytes(hex(RUST_TEST_SK));
        PublicKey child = sk.getPublicKey().deriveUnhardened(0xFFFFFFFF);
        assertEquals("b8b397a9bf38bcf6106f1c555aba0f799d1a37549e8893b8416c5315c561688d3c8a3a8a4aa3287af9b40b3b01187de2", child.toString());
        assertEquals(child, sk.deriveUnhardened(-1).getPublicKey());
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
        assertEquals("924c956ff652c5471e1a45d1639459c9efac8369809f5cf2f098f253d672b4733ac1f7b82fa5a59c386c49fd2336280b0ecbcc4b04c4f67d53cc77f8bc0f18efdf9e1300213d950ac0dddd08828636b96f8162e2ec847540c2e88e0060ddfd45", signature.toString());
        assertEquals(child, signature.deriveUnhardened((int) index).toString());
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
