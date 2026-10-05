package surf.superhighway.bls;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

/**
 * A cache of pairings {@code e(pk, hashToG2(pk || msg))} keyed by {@code sha256(pk || msg)}, as
 * chia-bls {@code BlsCache}. It speeds up aggregate verification when the same (key, message)
 * pairs recur, e.g. transactions seen in the mempool and again in a block. Without cache hits,
 * {@link Bls#aggregateVerify} is faster.
 *
 * <p>When full, the oldest entry is dropped; re-inserting a key moves it to the newest position,
 * and lookups do not. Thread-safe.
 */
public final class BlsCache {

    public static final int DEFAULT_CAPACITY = 50_000;

    private final int capacity;
    private final LinkedHashMap<ByteBuffer, GTElement> items = new LinkedHashMap<>();

    public BlsCache() {
        this(DEFAULT_CAPACITY);
    }

    /** @param capacity maximum number of cached pairings; must be positive */
    public BlsCache(int capacity) {
        if (capacity < 1) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.capacity = capacity;
    }

    private BlsCache(BlsCache other) {
        synchronized (other) {
            this.capacity = other.capacity;
            this.items.putAll(other.items);
        }
    }

    /** An independent copy with the same entries. */
    public BlsCache copy() {
        return new BlsCache(this);
    }

    public synchronized int size() {
        return items.size();
    }

    public synchronized boolean isEmpty() {
        return items.isEmpty();
    }

    /**
     * Same result as {@link Bls#aggregateVerify}, using and filling the cache. Unlike chia-bls,
     * a public key outside G1 is rejected before any pairing is computed or cached.
     *
     * @throws IllegalArgumentException if the lists differ in size
     */
    public boolean aggregateVerify(List<PublicKey> publicKeys, List<byte[]> messages, Signature signature) {
        Objects.requireNonNull(publicKeys, "publicKeys");
        Objects.requireNonNull(messages, "messages");
        Objects.requireNonNull(signature, "signature");
        if (publicKeys.size() != messages.size()) {
            throw new IllegalArgumentException("The number of public keys must match the number of messages");
        }
        // aggregate_verify_gt checks the signature before any pairing is computed.
        if (!signature.isValid()) {
            return false;
        }

        List<GTElement> pairings = new ArrayList<>(publicKeys.size());
        for (int i = 0; i < publicKeys.size(); i++) {
            PublicKey publicKey = Objects.requireNonNull(publicKeys.get(i), "publicKeys contains null");
            byte[] message = Objects.requireNonNull(messages.get(i), "messages contains null");
            if (!publicKey.isValid()) {
                return false;
            }
            byte[] augmented = Bytes.concat(publicKey.bytesUnsafe(), message);
            ByteBuffer key = ByteBuffer.wrap(Bytes.sha256(augmented));

            GTElement pairing = get(key);
            if (pairing == null) {
                pairing = Bls.hashToG2(augmented).pair(publicKey);
                put(key, pairing);
            }
            pairings.add(pairing);
        }
        return Bls.aggregateVerifyGt(signature, pairings);
    }

    /** Caches {@code pairing} for the augmented message {@code pk || msg}. chia-bls {@code update}. */
    public void update(byte[] augmentedMessage, GTElement pairing) {
        Objects.requireNonNull(augmentedMessage, "augmentedMessage");
        Objects.requireNonNull(pairing, "pairing");
        put(ByteBuffer.wrap(Bytes.sha256(augmentedMessage)), pairing);
    }

    /** Removes the entries for the given (key, message) pairs. chia-bls {@code evict}. */
    public void evict(List<PublicKey> publicKeys, List<byte[]> messages) {
        Objects.requireNonNull(publicKeys, "publicKeys");
        Objects.requireNonNull(messages, "messages");
        if (publicKeys.size() != messages.size()) {
            throw new IllegalArgumentException("The number of public keys must match the number of messages");
        }
        synchronized (this) {
            for (int i = 0; i < publicKeys.size(); i++) {
                byte[] augmented = Bytes.concat(publicKeys.get(i).bytesUnsafe(), messages.get(i));
                items.remove(ByteBuffer.wrap(Bytes.sha256(augmented)));
            }
        }
    }

    synchronized boolean containsHash(byte[] hash) {
        return items.containsKey(ByteBuffer.wrap(hash));
    }

    private synchronized GTElement get(ByteBuffer key) {
        return items.get(key);
    }

    private synchronized void put(ByteBuffer key, GTElement pairing) {
        if (items.size() == capacity) {
            Iterator<ByteBuffer> oldest = items.keySet().iterator();
            oldest.next();
            oldest.remove();
        }
        items.remove(key);          // re-insertion moves the entry to the newest position
        items.put(key, pairing);
    }
}
