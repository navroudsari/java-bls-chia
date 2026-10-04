package surf.superhighway.bls;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.hex;
import static surf.superhighway.bls.TestBytes.of;
import static surf.superhighway.bls.TestBytes.repeat;

/** Test vectors from Chia's bls-signatures test suite. */
class ChiaVectorsTest {

    @Test
    void basicSchemeChiaVectors() {
        BasicSignatureScheme basic = BasicSignatureScheme.getInstance();

        PrivateKey sk1 = PrivateKey.fromSeed(repeat(0, 32));
        PrivateKey sk2 = PrivateKey.fromSeed(repeat(1, 32));

        PublicKey pk1 = sk1.getPublicKey();
        PublicKey pk2 = sk2.getPublicKey();

        byte[] msg1 = of(7, 8, 9);
        byte[] msg2 = of(10, 11, 12);

        Signature sig1 = basic.sign(sk1, msg1);
        Signature sig2 = basic.sign(sk2, msg2);

        assertEquals(0xb40dd58aL, pk1.getFingerprint());
        assertEquals(0xb839add1L, pk2.getFingerprint());

        assertEquals("b8faa6d6a3881c9fdbad803b170d70ca5cbf1e6ba5a586262df368c75acd1d1ffa3ab6ee21c71f844494659878f5eb230c958dd576b08b8564aad2ee0992e85a1e565f299cd53a285de729937f70dc176a1f01432129bb2b94d3d5031f8065a1", sig1.toString());
        assertEquals("a9c4d3e689b82c7ec7e838dac2380cb014f9a08f6cd6ba044c263746e39a8f7a60ffee4afb78f146c2e421360784d58f0029491e3bd8ab84f0011d258471ba4e87059de295d9aba845c044ee83f6cf2411efd379ef38bf4cf41d5f3c0ae1205d", sig2.toString());

        Signature aggSig1 = basic.aggregateSignatures(List.of(sig1, sig2));
        assertEquals("aee003c8cdaf3531b6b0ca354031b0819f7586b5846796615aee8108fec75ef838d181f9d244a94d195d7b0231d4afcf06f27f0cc4d3c72162545c240de7d5034a7ef3a2a03c0159de982fbc2e7790aeb455e27beae91d64e077c70b5506dea3", aggSig1.toString());

        assertTrue(basic.aggregateVerify(List.of(pk1, pk2), List.of(msg1, msg2), aggSig1));
        assertFalse(basic.aggregateVerify(List.of(pk1, pk2), List.of(msg1, msg2), sig1));
        assertFalse(basic.verify(pk1, msg1, sig2));
        assertFalse(basic.verify(pk2, msg2, sig1));

        byte[] msg3 = of(1, 2, 3);
        byte[] msg4 = of(1, 2, 3, 4);
        byte[] msg5 = of(1, 2);

        Signature sig3 = basic.sign(sk1, msg3);
        Signature sig4 = basic.sign(sk1, msg4);
        Signature sig5 = basic.sign(sk2, msg5);

        Signature aggSig2 = basic.aggregateSignatures(List.of(sig3, sig4, sig5));

        assertTrue(basic.aggregateVerify(List.of(pk1, pk1, pk2), List.of(msg3, msg4, msg5), aggSig2));
        assertEquals("a0b1378d518bea4d1100adbc7bdbc4ff64f2c219ed6395cd36fe5d2aa44a4b8e710b607afd965e505a5ac3283291b75413d09478ab4b5cfbafbeea366de2d0c0bcf61deddaa521f6020460fd547ab37659ae207968b545727beba0a3c5572b9c", aggSig2.toString());
    }

    @Test
    void augSchemeChiaVectors() {
        byte[] message1 = of(1, 2, 3, 40);
        byte[] message2 = of(5, 6, 70, 201);
        byte[] message3 = of(9, 10, 11, 12, 13);
        byte[] message4 = of(15, 63, 244, 92, 0, 1);

        PrivateKey privateKey1 = PrivateKey.fromSeed(repeat(0x02, 32));
        PrivateKey privateKey2 = PrivateKey.fromSeed(repeat(0x03, 32));

        PublicKey publicKey1 = privateKey1.getPublicKey();
        PublicKey publicKey2 = privateKey2.getPublicKey();

        MessageAugmentationSignatureScheme aug = MessageAugmentationSignatureScheme.getInstance();
        Signature signature1 = aug.sign(privateKey1, message1);
        Signature signature2 = aug.sign(privateKey2, message2);
        Signature signature3 = aug.sign(privateKey2, message1);
        Signature signature4 = aug.sign(privateKey1, message3);
        Signature signature5 = aug.sign(privateKey1, message1);
        Signature signature6 = aug.sign(privateKey1, message4);

        Signature aggregateL = aug.aggregateSignatures(List.of(signature1, signature2));
        Signature aggregateR = aug.aggregateSignatures(List.of(signature3, signature4, signature5));
        Signature aggregate = aug.aggregateSignatures(List.of(aggregateL, aggregateR, signature6));

        assertTrue(aug.aggregateVerify(
                List.of(publicKey1, publicKey2, publicKey2, publicKey1, publicKey1, publicKey1),
                List.of(message1, message2, message1, message3, message1, message4), aggregate));

        assertEquals("a1d5360dcb418d33b29b90b912b4accde535cf0e52caf467a005dc632d9f7af44b6c4e9acd46eac218b28cdb07a3e3bc087df1cd1e3213aa4e11322a3ff3847bbba0b2fd19ddc25ca964871997b9bceeab37a4c2565876da19382ea32a962200", hex(aggregate.toBytes()));
    }

    @Test
    void popSchemeChiaVectors() {
        ProofOfPossessionSignatureScheme pop = ProofOfPossessionSignatureScheme.getInstance();
        PrivateKey privateKey = PrivateKey.fromSeed(repeat(0x04, 32));

        Signature proof = pop.popProve(privateKey);
        assertTrue(pop.popVerify(privateKey.getPublicKey(), proof));

        assertEquals("84f709159435f0dc73b3e8bf6c78d85282d19231555a8ee3b6e2573aaf66872d9203fefa1ef700e34e7c3f3fb28210100558c6871c53f1ef6055b9f06b0d1abe22ad584ad3b957f3018a8f58227c6c716b1e15791459850f2289168fa0cf9115", hex(proof.toBytes()));
    }
}
