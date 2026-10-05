package surf.superhighway.bls;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.repeat;

/** Port of the tests in chia_rs {@code crates/chia-bls/src/bls_cache.rs} (chia_rs 6485640). */
class RustBlsCacheTest {

    private static byte[] cacheKey(PublicKey pk, byte[] msg) {
        return Bytes.sha256(Bytes.concat(pk.toBytes(), msg));
    }

    @Test
    void testAggregateVerify() {
        BlsCache cache = new BlsCache();
        PrivateKey sk = PrivateKey.fromSeed(repeat(0, 32));
        PublicKey pk = sk.getPublicKey();
        byte[] msg = repeat(106, 32);
        Signature sig = Bls.sign(sk, msg);

        // Before we cache anything, it should be empty.
        assertTrue(cache.isEmpty());

        // Verify the signature and add to the cache.
        assertTrue(cache.aggregateVerify(List.of(pk), List.of(msg), sig));
        assertEquals(1, cache.size());

        // Now that it's cached, it shouldn't cache it again.
        assertTrue(cache.aggregateVerify(List.of(pk), List.of(msg), sig));
        assertEquals(1, cache.size());
    }

    @Test
    void testCache() {
        BlsCache cache = new BlsCache();
        PrivateKey sk1 = PrivateKey.fromSeed(repeat(0, 32));
        byte[] msg1 = repeat(106, 32);
        Signature aggSig = Bls.sign(sk1, msg1);
        List<PublicKey> pks = new ArrayList<>(List.of(sk1.getPublicKey()));
        List<byte[]> msgs = new ArrayList<>(List.of(msg1));

        assertTrue(cache.isEmpty());

        // Add the first signature to cache.
        assertTrue(cache.aggregateVerify(pks, msgs, aggSig));
        assertEquals(1, cache.size());

        // Try with the first key message pair in the cache but not the second.
        PrivateKey sk2 = PrivateKey.fromSeed(repeat(1, 32));
        byte[] msg2 = repeat(107, 32);
        aggSig = aggSig.add(Bls.sign(sk2, msg2));
        pks.add(sk2.getPublicKey());
        msgs.add(msg2);

        assertTrue(cache.aggregateVerify(pks, msgs, aggSig));
        assertEquals(2, cache.size());

        // Try reusing a public key.
        byte[] msg3 = repeat(108, 32);
        aggSig = aggSig.add(Bls.sign(sk2, msg3));
        pks.add(sk2.getPublicKey());
        msgs.add(msg3);

        // Verify this signature and add to the cache as well (since it's still a different aggregate).
        assertTrue(cache.aggregateVerify(pks, msgs, aggSig));
        assertEquals(3, cache.size());
    }

    @Test
    void testCacheLimit() {
        // The cache is limited to only 3 items.
        BlsCache cache = new BlsCache(3);
        assertTrue(cache.isEmpty());

        // Create 5 pubkey message pairs and add them by validating one at a time.
        for (int i = 1; i <= 5; i++) {
            PrivateKey sk = PrivateKey.fromSeed(repeat(i, 32));
            byte[] msg = repeat(106, 32);
            assertTrue(cache.aggregateVerify(List.of(sk.getPublicKey()), List.of(msg), Bls.sign(sk, msg)));
        }

        // The cache should be full now.
        assertEquals(3, cache.size());

        // Recreate first two keys and make sure they got removed.
        for (int i = 1; i <= 2; i++) {
            PublicKey pk = PrivateKey.fromSeed(repeat(i, 32)).getPublicKey();
            assertFalse(cache.containsHash(cacheKey(pk, repeat(106, 32))));
        }
    }

    @Test
    void testEmptySig() {
        assertTrue(new BlsCache().aggregateVerify(List.of(), List.of(), Signature.infinity()));
    }

    @Test
    void testEvict() {
        BlsCache cache = new BlsCache(5);
        // Create 5 pk msg pairs and add them to the cache.
        List<PublicKey> pks = new ArrayList<>();
        byte[] msg = repeat(42, 32);
        for (int i = 1; i <= 5; i++) {
            PrivateKey sk = PrivateKey.fromSeed(repeat(i, 32));
            pks.add(sk.getPublicKey());
            assertTrue(cache.aggregateVerify(List.of(sk.getPublicKey()), List.of(msg), Bls.sign(sk, msg)));
        }
        assertEquals(5, cache.size());

        // Evict the first and third entries.
        cache.evict(List.of(pks.get(0), pks.get(2)), List.of(msg, msg));
        assertEquals(3, cache.size());

        // Check that the evicted entries are no longer in the cache.
        assertFalse(cache.containsHash(cacheKey(pks.get(0), msg)));
        assertFalse(cache.containsHash(cacheKey(pks.get(2), msg)));
        // Check that the remaining entries are still in the cache.
        for (int i : new int[]{1, 3, 4}) {
            assertTrue(cache.containsHash(cacheKey(pks.get(i), msg)));
        }
    }
}
