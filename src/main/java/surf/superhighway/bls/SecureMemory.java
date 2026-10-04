package surf.superhighway.bls;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Off-heap storage for secret scalars.
 *
 * <p>Secret keys live in fixed 32-byte slots carved out of 64 KiB slabs allocated outside the
 * Java heap, so the garbage collector never copies them. Each slab is, best effort, locked into
 * RAM ({@code mlock} / {@code VirtualLock}) so it is not written to swap, and on Linux excluded
 * from core dumps ({@code MADV_DONTDUMP}). Freed slots are zeroized before reuse. Slabs are kept
 * for the life of the process.
 *
 * <p>Short-lived secrets of arbitrary size (seeds, big-endian scalar encodings) use
 * {@link #withWipedBuffer}, which zeroizes a confined native buffer before releasing it.
 */
final class SecureMemory {

    static final long SLOT_SIZE = Blst.SCALAR_SIZE;
    private static final long SLAB_SIZE = 64 * 1024;
    private static final long SLAB_ALIGNMENT = 64 * 1024;   // covers 4K, 16K and 64K pages
    private static final int SLOTS_PER_SLAB = (int) (SLAB_SIZE / SLOT_SIZE);
    private static final int MADV_DONTDUMP = 16;            // Linux

    private static final List<Slab> SLABS = new ArrayList<>();

    private static final MethodHandle LOCK;
    private static final MethodHandle MADVISE;

    static {
        Linker linker = Linker.nativeLinker();
        MethodHandle lock = null;
        MethodHandle madvise = null;
        try {
            if (NativeLibrary.OS.equals("windows")) {
                SymbolLookup kernel32 = SymbolLookup.libraryLookup("kernel32", Arena.global());
                lock = find(linker, kernel32, "VirtualLock", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG));
            } else {
                SymbolLookup libc = linker.defaultLookup();
                lock = find(linker, libc, "mlock", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG));
                if (NativeLibrary.OS.equals("linux")) {
                    madvise = find(linker, libc, "madvise", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT));
                }
            }
        } catch (RuntimeException e) {
            // Memory locking is best effort; keys still live off-heap and are zeroized.
        }
        LOCK = lock;
        MADVISE = madvise;
    }

    private SecureMemory() {
    }

    private static MethodHandle find(Linker linker, SymbolLookup lookup, String name, FunctionDescriptor descriptor) {
        Optional<MemorySegment> symbol = lookup.find(name);
        return symbol.map(s -> linker.downcallHandle(s, descriptor)).orElse(null);
    }

    /** A 32-byte secret slot. */
    record Slot(Slab slab, int index, MemorySegment segment) {
    }

    static final class Slab {
        private final MemorySegment memory;
        private final BitSet used = new BitSet(SLOTS_PER_SLAB);
        private final boolean locked;

        private Slab() {
            memory = Arena.global().allocate(SLAB_SIZE, SLAB_ALIGNMENT);
            locked = lock(memory);
            excludeFromCoreDumps(memory);
        }

        boolean isLocked() {
            return locked;
        }
    }

    /** Allocates a zeroed 32-byte slot for a secret scalar. */
    static synchronized Slot allocate() {
        for (Slab slab : SLABS) {
            int index = slab.used.nextClearBit(0);
            if (index < SLOTS_PER_SLAB) {
                return take(slab, index);
            }
        }
        Slab slab = new Slab();
        SLABS.add(slab);
        return take(slab, 0);
    }

    private static Slot take(Slab slab, int index) {
        slab.used.set(index);
        MemorySegment segment = slab.memory.asSlice(index * SLOT_SIZE, SLOT_SIZE);
        return new Slot(slab, index, segment);
    }

    /** Zeroizes a slot and returns it to its slab. Must be called at most once per slot. */
    static synchronized void free(Slot slot) {
        Blst.zeroize(slot.segment());
        slot.slab().used.clear(slot.index());
    }

    /**
     * Runs {@code action} with a zeroed native buffer of {@code size} bytes and zeroizes the
     * buffer afterwards, whether or not {@code action} throws.
     */
    static <T> T withWipedBuffer(long size, Function<MemorySegment, T> action) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buffer = arena.allocate(Math.max(size, 1), Blst.ALIGNMENT);
            try {
                return action.apply(buffer);
            } finally {
                Blst.zeroize(buffer);
            }
        }
    }

    private static boolean lock(MemorySegment memory) {
        if (LOCK == null) {
            return false;
        }
        try {
            int result = (int) LOCK.invokeExact(memory, memory.byteSize());
            // mlock returns 0 on success; VirtualLock returns non-zero on success.
            return NativeLibrary.OS.equals("windows") ? result != 0 : result == 0;
        } catch (Throwable t) {
            return false;
        }
    }

    private static void excludeFromCoreDumps(MemorySegment memory) {
        if (MADVISE == null) {
            return;
        }
        try {
            int ignored = (int) MADVISE.invokeExact(memory, memory.byteSize(), MADV_DONTDUMP);
        } catch (Throwable t) {
            // best effort
        }
    }
}
