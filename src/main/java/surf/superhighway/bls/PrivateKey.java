package surf.superhighway.bls;

import javax.security.auth.Destroyable;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.function.Function;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * A BLS12-381 secret key (a scalar modulo the group order r).
 *
 * <h2>Memory handling</h2>
 * The scalar is stored outside the Java heap, in memory that is locked against swapping where
 * the OS allows it (see {@link #isMemoryLocked()}), so the garbage collector never copies it.
 * Every operation on the key (signing, derivation, aggregation) runs in native code on that
 * memory directly. Call {@link #destroy()} (or use try-with-resources) as soon as a key is no
 * longer needed: its memory is zeroized immediately and any further use throws
 * {@link IllegalStateException}. Keys that become unreachable without being destroyed are
 * zeroized by a {@link Cleaner}, at a time the garbage collector chooses.
 *
 * <p>The byte-array entry points ({@link #fromBytes}, {@link #fromSeed}, {@link #toBytes}) are
 * the only places secret material crosses the Java heap; callers own those arrays and should
 * overwrite them (e.g. {@code Arrays.fill(bytes, (byte) 0)}) when done.
 *
 * <p>Instances are thread-safe. {@link #toString()} never reveals key material, and
 * {@link #equals} compares in constant time.
 */
public final class PrivateKey implements Destroyable, AutoCloseable {

    public static final int SIZE = 32;

    /** Seeds shorter than this are rejected, as in Chia and draft-irtf-cfrg-bls-signature. */
    public static final int MIN_SEED_SIZE = 32;

    private static final Cleaner CLEANER = Cleaner.create();
    private static final AtomicLong SEQUENCE = new AtomicLong();

    private final SecureMemory.Slot slot;
    private final Cleaner.Cleanable cleanable;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final long sequence = SEQUENCE.getAndIncrement();   // lock ordering in equals()
    private final PublicKey publicKey;
    private volatile boolean destroyed;                        // written under the write lock

    private PrivateKey(SecureMemory.Slot slot) {
        MemorySegment point = PublicKey.newPoint();
        Blst.skToPkInG1(point, slot.segment());
        this.publicKey = PublicKey.fromPoint(point);
        this.slot = slot;
        // Registered last: if anything above throws, create() frees the slot instead.
        this.cleanable = CLEANER.register(this, new Release(slot));
    }

    /** Cleaner action; must not reference the PrivateKey. */
    private record Release(SecureMemory.Slot slot) implements Runnable {
        @Override
        public void run() {
            SecureMemory.free(slot);
        }
    }

    private static PrivateKey create(Consumer<MemorySegment> initializer) {
        SecureMemory.Slot slot = SecureMemory.allocate();
        try {
            initializer.accept(slot.segment());
            return new PrivateKey(slot);
        } catch (RuntimeException | Error e) {
            SecureMemory.free(slot);
            throw e;
        }
    }

    /**
     * Generates a key from a seed using KeyGen from draft-irtf-cfrg-bls-signature-03, as Chia
     * does ({@code AugSchemeMPL.key_gen}, chia-bls {@code SecretKey::from_seed}).
     *
     * @param seed at least {@value #MIN_SEED_SIZE} bytes of high-entropy secret material
     */
    public static PrivateKey fromSeed(byte[] seed) {
        Objects.requireNonNull(seed, "seed");
        if (seed.length < MIN_SEED_SIZE) {
            throw new IllegalArgumentException("Seed must be at least " + MIN_SEED_SIZE + " bytes");
        }
        return create(sk -> SecureMemory.withWipedBuffer(seed.length, buffer -> {
            MemorySegment.copy(seed, 0, buffer, JAVA_BYTE, 0, seed.length);
            Blst.keygenV3(sk, buffer, seed.length);
            return null;
        }));
    }

    /**
     * Parses a 32-byte big-endian key. The all-zero key is accepted (as Chia does); any other
     * value must be less than the group order.
     *
     * @throws BlsException ({@link BlsException.Kind#SECRET_KEY_GROUP_ORDER}) if the value is
     *                       not less than the group order
     */
    public static PrivateKey fromBytes(byte[] bytes) {
        Bytes.requireLength(bytes, SIZE, "private key");
        boolean zero = Bytes.allZero(bytes, 0);
        return create(sk -> {
            // blst_scalar is little-endian; reverse straight into secure memory.
            for (int i = 0; i < SIZE; i++) {
                sk.set(JAVA_BYTE, i, bytes[SIZE - 1 - i]);
            }
            if (!zero && !Blst.skCheck(sk)) {
                throw BlsException.of(BlsException.Kind.SECRET_KEY_GROUP_ORDER);
            }
        });
    }

    /** Parses 32 bytes as an unsigned big-endian integer and reduces it modulo the group order. */
    public static PrivateKey fromBytesModOrder(byte[] bytes) {
        Bytes.requireLength(bytes, SIZE, "private key");
        return create(sk -> SecureMemory.withWipedBuffer(SIZE, buffer -> {
            MemorySegment.copy(bytes, 0, buffer, JAVA_BYTE, 0, SIZE);
            Blst.scalarFromBeBytes(sk, buffer, SIZE);
            return null;
        }));
    }

    /**
     * Sums keys modulo the group order; the result's public key is the sum of the public keys.
     *
     * @throws IllegalArgumentException if the list is empty
     */
    public static PrivateKey aggregate(List<PrivateKey> privateKeys) {
        Objects.requireNonNull(privateKeys, "privateKeys");
        if (privateKeys.isEmpty()) {
            throw new IllegalArgumentException("Number of private keys must be at least 1");
        }
        return create(sum -> {
            for (PrivateKey key : privateKeys) {
                Objects.requireNonNull(key, "privateKeys contains null");
                key.withScalar(sk -> Blst.skAddNCheck(sum, sum, sk));
            }
        });
    }

    /** {@code this + other} modulo the group order, as chia-bls {@code SecretKey + SecretKey}. */
    public PrivateKey add(PrivateKey other) {
        Objects.requireNonNull(other, "other");
        return aggregate(List.of(this, other));
    }

    /**
     * The key as lowercase hex, as chia-bls {@code SecretKey::as_hex_string}. A Java
     * {@code String} cannot be wiped, so prefer {@link #toBytes()} unless you need text.
     */
    public String asHexString() {
        byte[] bytes = toBytes();
        try {
            return HexFormat.of().formatHex(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /** The 32-byte big-endian encoding. The caller owns the returned array and should wipe it. */
    public byte[] toBytes() {
        return withScalar(sk -> {
            byte[] out = new byte[SIZE];
            for (int i = 0; i < SIZE; i++) {
                out[i] = sk.get(JAVA_BYTE, SIZE - 1 - i);
            }
            return out;
        });
    }

    /** The corresponding public key. Remains available after {@link #destroy()}. */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Hardened child derivation, matching Chia ({@code AugSchemeMPL.derive_child_sk}, chia-bls
     * {@code SecretKey::derive_hardened}): EIP-2333's Lamport construction followed by KeyGen v3.
     * Runs entirely in native code; intermediate secrets are scrubbed before returning.
     *
     * @param index child index, 0 to 4294967295 (a Rust {@code u32})
     * @throws IllegalArgumentException if {@code index} is outside that range
     */
    public PrivateKey deriveHardened(long index) {
        int childIndex = Bytes.childIndex(index);
        return create(child -> withScalar(parent -> {
            Blst.chiaDeriveChildSk(child, parent, childIndex);
            return null;
        }));
    }

    /**
     * Unhardened (BIP32-style) child derivation, matching chia-bls
     * {@code SecretKey::derive_unhardened}. The child's public key equals
     * {@code getPublicKey().deriveUnhardened(index)}.
     *
     * @param index child index, 0 to 4294967295 (a Rust {@code u32})
     * @throws IllegalArgumentException if {@code index} is outside that range
     */
    public PrivateKey deriveUnhardened(long index) {
        byte[] digest = Bytes.sha256(publicKey.bytesUnsafe(), Bytes.uint32(index));
        return create(child -> {
            try (Arena arena = Arena.ofConfined()) {
                Blst.scalarFromBeBytes(child, arena.allocateFrom(JAVA_BYTE, digest), digest.length);
            }
            withScalar(parent -> Blst.skAddNCheck(child, child, parent));
        });
    }

    /** An independent copy that can be destroyed separately. */
    public PrivateKey copy() {
        return create(target -> withScalar(source -> {
            MemorySegment.copy(source, 0, target, 0, SIZE);
            return null;
        }));
    }

    /** Signs {@code message} hashed to G2 with domain separation tag {@code dst}. */
    Signature sign(byte[] message, byte[] dst) {
        MemorySegment signature = Signature.newPoint();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment msg = arena.allocate(Math.max(message.length, 1));
            MemorySegment.copy(message, 0, msg, JAVA_BYTE, 0, message.length);
            MemorySegment tag = arena.allocateFrom(JAVA_BYTE, dst);
            MemorySegment hash = arena.allocate(Blst.P2_SIZE, Blst.ALIGNMENT);
            Blst.hashToG2(hash, msg, message.length, tag, dst.length);
            withScalar(sk -> {
                Blst.signPkInG1(signature, hash, sk);
                return null;
            });
        }
        return Signature.fromPoint(signature);
    }

    private <T> T withScalar(Function<MemorySegment, T> action) {
        Lock read = lock.readLock();
        read.lock();
        try {
            if (destroyed) {
                throw new IllegalStateException("PrivateKey has been destroyed");
            }
            return action.apply(slot.segment());
        } finally {
            read.unlock();
            Reference.reachabilityFence(this);
        }
    }

    /** True if the key's memory is locked against swapping (best effort; depends on OS limits). */
    public boolean isMemoryLocked() {
        return slot.slab().isLocked();
    }

    /** Zeroizes the key immediately. Idempotent; later operations throw IllegalStateException. */
    @Override
    public void destroy() {
        Lock write = lock.writeLock();
        write.lock();
        try {
            if (!destroyed) {
                destroyed = true;
                cleanable.clean();
            }
        } finally {
            write.unlock();
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    /** Same as {@link #destroy()}. */
    @Override
    public void close() {
        destroy();
    }

    /** Constant-time comparison. A destroyed key is only equal to itself. */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PrivateKey other)) {
            return false;
        }
        PrivateKey first = sequence < other.sequence ? this : other;
        PrivateKey second = first == this ? other : this;
        Lock firstLock = first.lock.readLock();
        Lock secondLock = second.lock.readLock();
        firstLock.lock();
        try {
            secondLock.lock();
            try {
                if (destroyed || other.destroyed) {
                    return false;
                }
                return Blst.chiaScalarEq(slot.segment(), other.slot.segment());
            } finally {
                secondLock.unlock();
            }
        } finally {
            firstLock.unlock();
            Reference.reachabilityFence(this);
            Reference.reachabilityFence(other);
        }
    }

    @Override
    public int hashCode() {
        return publicKey.hashCode();
    }

    /** Never reveals key material. */
    @Override
    public String toString() {
        return "<PrivateKey>";
    }
}
