package surf.superhighway.bls;

import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static surf.superhighway.bls.TestBytes.of;
import static surf.superhighway.bls.TestBytes.random;
import static surf.superhighway.bls.TestBytes.repeat;

class SecureMemoryTest {

    private static MemorySegment slotOf(PrivateKey key) throws ReflectiveOperationException {
        Field field = PrivateKey.class.getDeclaredField("slot");
        field.setAccessible(true);
        return ((SecureMemory.Slot) field.get(key)).segment();
    }

    private static boolean isZero(MemorySegment segment) {
        for (long i = 0; i < segment.byteSize(); i++) {
            if (segment.get(JAVA_BYTE, i) != 0) {
                return false;
            }
        }
        return true;
    }

    @Test
    void keyMaterialLivesOffHeap() throws ReflectiveOperationException {
        PrivateKey key = PrivateKey.fromSeed(random(32));
        MemorySegment slot = slotOf(key);
        assertTrue(slot.isNative());
        assertEquals(PrivateKey.SIZE, slot.byteSize());
        assertFalse(isZero(slot));
        assertDoesNotThrow(key::isMemoryLocked);
    }

    @Test
    void destroyZeroizesImmediately() throws ReflectiveOperationException {
        PrivateKey key = PrivateKey.fromSeed(random(32));
        MemorySegment slot = slotOf(key);

        key.destroy();

        assertTrue(key.isDestroyed());
        assertTrue(isZero(slot));
        key.destroy(); // idempotent
    }

    @Test
    void useAfterDestroyThrows() {
        PrivateKey key = PrivateKey.fromSeed(random(32));
        PublicKey publicKey = key.getPublicKey();
        key.destroy();

        assertThrows(IllegalStateException.class, key::toBytes);
        assertThrows(IllegalStateException.class, key::copy);
        assertThrows(IllegalStateException.class, () -> key.deriveHardened(0));
        assertThrows(IllegalStateException.class, () -> key.deriveUnhardened(0));
        assertThrows(IllegalStateException.class, () -> PrivateKey.aggregate(List.of(key)));
        assertThrows(IllegalStateException.class, () -> BasicSignatureScheme.getInstance().sign(key, of(1)));

        assertEquals(publicKey, key.getPublicKey(), "public key stays available");
        assertEquals(key, key);
        assertNotEquals(key, PrivateKey.fromBytes(new byte[32]));
    }

    @Test
    void tryWithResourcesDestroys() {
        PrivateKey escaped;
        try (PrivateKey key = PrivateKey.fromSeed(random(32))) {
            escaped = key;
            assertFalse(key.isDestroyed());
        }
        assertTrue(escaped.isDestroyed());
    }

    @Test
    void destroyingACopyLeavesTheOriginalUsable() {
        PrivateKey original = PrivateKey.fromSeed(repeat(9, 32));
        PrivateKey copy = original.copy();
        copy.destroy();
        assertEquals(PrivateKey.fromSeed(repeat(9, 32)), original);
    }

    @Test
    void failedParsingReleasesTheSlot() throws ReflectiveOperationException {
        byte[] tooLarge = repeat(0xff, 32);
        assertThrows(IllegalArgumentException.class, () -> PrivateKey.fromBytes(tooLarge));
        // The slot is zeroized and reused: the next key gets clean memory and works normally.
        PrivateKey next = PrivateKey.fromSeed(repeat(3, 32));
        assertEquals(PrivateKey.fromSeed(repeat(3, 32)), next);
        assertFalse(isZero(slotOf(next)));
    }

    @Test
    void manyKeysSpanSeveralSlabs() {
        List<PrivateKey> keys = new ArrayList<>();
        for (int i = 0; i < 2100; i++) {   // more than one 64 KiB slab of 32-byte slots
            keys.add(PrivateKey.fromBytesModOrder(random(32)));
        }
        PrivateKey sum = PrivateKey.aggregate(keys);
        PublicKey expected = PublicKey.aggregate(keys.stream().map(PrivateKey::getPublicKey).toList());
        assertEquals(expected, sum.getPublicKey());
        keys.forEach(PrivateKey::destroy);
    }

    @Test
    void concurrentDestroyNeverSignsWithAnotherKeysMaterial() throws Exception {
        BasicSignatureScheme basic = BasicSignatureScheme.getInstance();
        byte[] message = of(1, 2, 3);
        int threads = 4;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int round = 0; round < 20; round++) {
                PrivateKey key = PrivateKey.fromSeed(random(32));
                PublicKey publicKey = key.getPublicKey();
                ConcurrentLinkedQueue<Signature> produced = new ConcurrentLinkedQueue<>();
                CountDownLatch start = new CountDownLatch(1);

                List<Future<?>> futures = new ArrayList<>();
                for (int t = 0; t < threads; t++) {
                    futures.add(pool.submit(() -> {
                        start.await();
                        for (int i = 0; i < 50; i++) {
                            try {
                                produced.add(basic.sign(key, message));
                            } catch (IllegalStateException destroyed) {
                                break;
                            }
                        }
                        return null;
                    }));
                }

                start.countDown();
                key.destroy();
                // Reuse the freed slot straight away with different key material.
                List<PrivateKey> others = new ArrayList<>();
                for (int i = 0; i < 8; i++) {
                    others.add(PrivateKey.fromSeed(random(32)));
                }
                for (Future<?> future : futures) {
                    future.get(30, TimeUnit.SECONDS);
                }

                for (Signature signature : produced) {
                    assertTrue(basic.verify(publicKey, message, signature));
                }
                others.forEach(PrivateKey::destroy);
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
