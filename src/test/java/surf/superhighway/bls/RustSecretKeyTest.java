package surf.superhighway.bls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static surf.superhighway.bls.TestBytes.hex;

/**
 * Port of the tests in chia_rs {@code crates/chia-bls/src/secret_key.rs} (chia_rs 6485640).
 * Rust's seeded {@code StdRng} is replaced by {@code java.util.Random(1337)}.
 */
class RustSecretKeyTest {

    private static final String SK_HEX = "52d75c4707e39595b27314547f9723e5530c01198af3fc5849d9a7af65631efb";

    private static byte[] fill(Random rng, int length) {
        byte[] out = new byte[length];
        rng.nextBytes(out);
        return out;
    }

    // test vectors from: chia.util.keychain KeyDataSecrets.from_mnemonic(phrase)["privatekey"]
    @ParameterizedTest
    @CsvSource({
            "fc795be0c3f18c50dddb34e72179dc597d64055497ecc1e69e2e56a5409651bc139aae8070d4df0ea14d8d2a518a9a00bb1cc6e92e053fe34051f6821df9164c, 52d75c4707e39595b27314547f9723e5530c01198af3fc5849d9a7af65631efb",
            "b873212f885ccffbf4692afcb84bc2e55886de2dfa07d90f5c3c239abc31c0a6ce047e30fd8bf6a281e71389aa82d73df74c7bbfb3b06b4639a5cee775cccd3c, 35d65c35d926f62ba2dd128754ddb556edb4e2c926237ab9e02a23e7b3533613",
            "3e066d7dee2dbf8fcd3fe240a3975658ca118a8f6f4ca81cf99104944604b05a5090a79d99e545704b914ca0397fedb82fd00fd6a72098703709c891a065ee49, 59095c391107936599b7ee6f09067979b321932bd62e23c7f53ed5fb19f851f6",
    })
    void testMakeKey(String seed, String sk) {
        assertEquals(sk, hex(PrivateKey.fromSeed(hex(seed)).toBytes()));
    }

    // test vectors from: blspy AugSchemeMPL.derive_child_sk_unhardened(sk, i)
    @ParameterizedTest
    @CsvSource({
            "0, 399638f99d446500f3c3a363f24c2b0634ad7caf646f503455093f35f29290bd",
            "1, 3dcb4098ad925d8940e2f516d2d5a4dbab393db928a8c6cb06b93066a09a843a",
            "2, 13115c8fb68a3d667938dac2ffc6b867a4a0f216bbb228aa43d6bdde14245575",
            "3, 52e7e9f2fb51f2c5705aea8e11ac82737b95e664ae578f015af22031d956f92b",
    })
    void testDeriveUnhardened(int index, String derived) {
        assertEquals(derived, hex(PrivateKey.fromBytes(hex(SK_HEX)).deriveUnhardened(index).toBytes()));
    }

    // test vectors from: blspy derive_child_sk_unhardened(sk, i) for i in [100, 52312, 352350, 316]
    @ParameterizedTest
    @CsvSource({
            "5aac8405befe4cb3748a67177c56df26355f1f98d979afdb0b2f97858d2f71c3, b9de000821a610ef644d160c810e35113742ff498002c2deccd8f1a349e423047e9b3fc17ebfc733dbee8fd902ba2961",
            "23f1fb291d3bd7434282578b842d5ea4785994bb89bd2c94896d1b4be6c70ba2, 96f304a5885e67abdeab5e1ed0576780a1368777ea7760124834529e8694a1837a20ffea107b9769c4f92a1f6c167e69",
            "2bc1d6d6efe58d365c29ccb7ad12c8457c0eec70a29003073692ac4cb1cd7ba2, b10568446def64b17fc9b6d614ae036deaac3f2d654e12e45ea04b19208246e0d760e8826426e97f9f0666b7ce340d75",
            "2bfc8672d859700e30aa6c8edc24a8ce9e6dc53bb1ef936f82de722847d05b9e, 9641472acbd6af7e5313d2500791b87117612af43eef929cf7975aaaa5a203a32698a8ef53763a84d90ad3f00b86ad66",
            "3311f883dad1e39c52bf82d5870d05371c0b1200576287b5160808f55568151b, 928ea102b5a3e3efe4f4c240d3458a568dfeb505e02901a85ed70a384944b0c08c703a35245322709921b8f2b7f5e54a",
    })
    void testPublicKey(String sk, String pk) {
        assertEquals(PublicKey.fromBytes(hex(pk)), PrivateKey.fromBytes(hex(sk)).getPublicKey());
    }

    // test vectors from: blspy AugSchemeMPL.derive_child_sk(sk, i)
    @ParameterizedTest
    @CsvSource({
            "0, 05eccb2d70e814f51a30d8b9965505605c677afa97228fa2419db583a8121db9",
            "1, 612ae96bdce2e9bc01693ac579918fbb559e04ec365cce9b66bb80e328f62c46",
            "2, 5df14a0a34fd6c30a80136d4103f0a93422ce82d5c537bebbecbc56e19fee5b9",
            "3, 3ea55db88d9a6bf5f1d9c9de072e3c9a56b13f4156d72fca7880cd39b4bd4fdc",
    })
    void testDeriveHardened(int index, String derived) {
        assertEquals(derived, hex(PrivateKey.fromBytes(hex(SK_HEX)).deriveHardened(index).toBytes()));
    }

    @Test
    void testDebug() {
        PrivateKey sk = PrivateKey.fromBytes(hex(SK_HEX));
        assertEquals("<PrivateKey>", sk.toString());
        assertEquals(SK_HEX, sk.asHexString());
    }

    @Test
    void testHash() {
        Random rng = new Random(1337);
        byte[] data = fill(rng, 32);
        PrivateKey sk1 = PrivateKey.fromSeed(data);
        PrivateKey sk2 = PrivateKey.fromSeed(data);
        PrivateKey sk3 = PrivateKey.fromSeed(fill(rng, 32));

        assertEquals(sk1.hashCode(), sk2.hashCode());
        assertNotEquals(sk1.hashCode(), sk3.hashCode());
    }

    @Test
    void testFromBytes() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            byte[] data = fill(rng, 32);
            data[0] |= (byte) 0x80;   // make the bytes exceed the group order
            BlsException e = assertThrows(BlsException.class, () -> PrivateKey.fromBytes(data));
            assertEquals(BlsException.Kind.SECRET_KEY_GROUP_ORDER, e.getKind());
            assertEquals("SecretKey byte data must be less than the group order", e.getMessage());
        }
    }

    @Test
    void testFromBytesZero() {
        PrivateKey.fromBytes(new byte[32]);
    }

    @Test
    void testAggregateSecretKey() {
        PrivateKey sk = PrivateKey.fromBytes(hex("5aac8405befe4cb3748a67177c56df26355f1f98d979afdb0b2f97858d2f71c3"));
        PrivateKey sk2 = sk.add(sk);
        PrivateKey sk3 = sk.add(sk).add(sk);

        assertEquals(PrivateKey.fromBytes(hex("416b60b8545f1c1eb5daf626ef0be64717009b2eb2f503b7165f2f0c1a5ee385")), sk2);
        assertEquals(PrivateKey.fromBytes(hex("282a3d6ae9bfeb89f72b853661c0ed67f8a216c48c705793218ec692a78e5547")), sk3);
    }

    @Test
    void testRoundtrip() {
        Random rng = new Random(1337);
        for (int i = 0; i < 50; i++) {
            PrivateKey sk = PrivateKey.fromSeed(fill(rng, 32));
            PrivateKey sk2 = PrivateKey.fromBytes(sk.toBytes());
            assertEquals(sk, sk2);
            assertEquals(sk.getPublicKey(), sk2.getPublicKey());
        }
    }
}
