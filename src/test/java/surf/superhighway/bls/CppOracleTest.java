package surf.superhighway.bls;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.hex;

/**
 * Vectors from Chia's C++ library (bls-signatures) for the features chia-bls (Rust) lacks: the
 * basic and proof-of-possession schemes and unhardened G2 derivation. See tools/oracle/.
 */
class CppOracleTest {

    private static List<String[]> rows(String resource) throws IOException {
        try (InputStream in = CppOracleTest.class.getResourceAsStream("/oracle/" + resource)) {
            assertNotNull(in, resource);
            List<String[]> rows = new ArrayList<>();
            for (String line : new String(in.readAllBytes(), StandardCharsets.US_ASCII).split("\\R")) {
                if (!line.isBlank() && !line.startsWith("#")) {
                    rows.add(line.split(",", -1));
                }
            }
            return rows;
        }
    }

    private static List<PrivateKey> keys(String field) {
        return Arrays.stream(field.split("\\|", -1)).map(h -> PrivateKey.fromBytes(hex(h))).toList();
    }

    private static List<byte[]> messages(String field) {
        return Arrays.stream(field.split("\\|", -1)).map(TestBytes::hex).toList();
    }

    @TestFactory
    Stream<DynamicTest> g2UnhardenedDerivation() throws IOException {
        return rows("g2_unhardened.csv").stream().map(row -> DynamicTest.dynamicTest(
                row[0].substring(0, 12) + "… index " + row[1], () -> {
                    Signature parent = Signature.fromBytes(hex(row[0]));
                    long index = Long.parseLong(row[1]);
                    assertEquals(row[2], hex(parent.deriveUnhardened(index).toBytes()));
                }));
    }

    @TestFactory
    Stream<DynamicTest> schemes() throws IOException {
        BasicSignatureScheme basic = BasicSignatureScheme.getInstance();
        ProofOfPossessionSignatureScheme pop = ProofOfPossessionSignatureScheme.getInstance();
        List<String[]> rows = rows("schemes.csv");
        return rows.stream().map(row -> DynamicTest.dynamicTest(row[0] + " #" + rows.indexOf(row), () -> {
            String kind = row[0];
            switch (kind) {
                case "basic_sign", "pop_sign" -> {
                    SignatureScheme scheme = kind.equals("basic_sign") ? basic : pop;
                    PrivateKey sk = PrivateKey.fromBytes(hex(row[1]));
                    byte[] message = hex(row[2]);
                    Signature signature = scheme.sign(sk, message);
                    assertEquals(row[3], hex(signature.toBytes()));
                    assertTrue(scheme.verify(sk.getPublicKey(), message, signature));
                }
                case "pop_prove" -> {
                    PrivateKey sk = PrivateKey.fromBytes(hex(row[1]));
                    Signature proof = pop.popProve(sk);
                    assertEquals(row[3], hex(proof.toBytes()));
                    assertTrue(pop.popVerify(sk.getPublicKey(), proof));
                }
                case "basic_aggregate_verify", "pop_aggregate_verify" -> {
                    SignatureScheme scheme = kind.startsWith("basic") ? basic : pop;
                    List<PrivateKey> sks = keys(row[1]);
                    List<byte[]> msgs = messages(row[2]);
                    String[] expected = row[3].split(":");
                    List<Signature> signatures = new ArrayList<>();
                    for (int i = 0; i < sks.size(); i++) {
                        signatures.add(scheme.sign(sks.get(i), msgs.get(i)));
                    }
                    Signature aggregate = scheme.aggregateSignatures(signatures);
                    assertEquals(expected[0], hex(aggregate.toBytes()));
                    List<PublicKey> pks = sks.stream().map(PrivateKey::getPublicKey).toList();
                    assertEquals(Boolean.parseBoolean(expected[1]), scheme.aggregateVerify(pks, msgs, aggregate));
                }
                case "pop_fast_aggregate_verify" -> {
                    List<PublicKey> pks = keys(row[1]).stream().map(PrivateKey::getPublicKey).toList();
                    String[] expected = row[3].split(":");
                    assertEquals(Boolean.parseBoolean(expected[1]),
                            pop.fastAggregateVerify(pks, hex(row[2]), Signature.fromBytes(hex(expected[0]))));
                }
                case "pop_verify" -> {
                    PublicKey pk = PrivateKey.fromBytes(hex(row[1])).getPublicKey();
                    String[] expected = row[3].split(":");
                    assertEquals(Boolean.parseBoolean(expected[1]), pop.popVerify(pk, Signature.fromBytes(hex(expected[0]))));
                }
                default -> throw new AssertionError("unknown vector kind " + kind);
            }
        }));
    }
}
