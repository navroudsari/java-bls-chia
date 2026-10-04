package surf.superhighway.bls;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BOOLEAN;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Foreign Function &amp; Memory bindings to blst and the chia_bls shim.
 *
 * <p>Each method mirrors one C function from {@code blst.h}, {@code blst_aux.h} or
 * {@code native/chia_bls.c}. Pointer arguments are native {@link MemorySegment}s of
 * the sizes below, aligned to {@link #ALIGNMENT}. C {@code bool} is {@code _Bool}.
 */
final class Blst {

    static final long ALIGNMENT = 8;
    static final long SCALAR_SIZE = 32;      // blst_scalar: 32 bytes, little-endian
    static final long P1_SIZE = 144;         // blst_p1: 3 x 48-byte field elements
    static final long P1_AFFINE_SIZE = 96;
    static final long P2_SIZE = 288;         // blst_p2: 3 x 96-byte Fp2 elements
    static final long P2_AFFINE_SIZE = 192;
    static final long FP12_SIZE = 576;

    static final int BLST_SUCCESS = 0;

    private static final Linker LINKER = Linker.nativeLinker();

    private static MethodHandle bind(String name, MemoryLayout result, MemoryLayout... args) {
        MemorySegment symbol = NativeLibrary.LOOKUP.find(name)
                .orElseThrow(() -> new UnsatisfiedLinkError("Native symbol not found: " + name));
        FunctionDescriptor descriptor = result == null ? FunctionDescriptor.ofVoid(args) : FunctionDescriptor.of(result, args);
        return LINKER.downcallHandle(symbol, descriptor);
    }

    private static final MethodHandle KEYGEN_V3 = bind("blst_keygen_v3", null, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG);
    private static final MethodHandle SCALAR_FROM_BE_BYTES = bind("blst_scalar_from_be_bytes", JAVA_BOOLEAN, ADDRESS, ADDRESS, JAVA_LONG);
    private static final MethodHandle SK_CHECK = bind("blst_sk_check", JAVA_BOOLEAN, ADDRESS);
    private static final MethodHandle SK_ADD_N_CHECK = bind("blst_sk_add_n_check", JAVA_BOOLEAN, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle SK_TO_PK_IN_G1 = bind("blst_sk_to_pk_in_g1", null, ADDRESS, ADDRESS);
    private static final MethodHandle SIGN_PK_IN_G1 = bind("blst_sign_pk_in_g1", null, ADDRESS, ADDRESS, ADDRESS);

    private static final MethodHandle P1_UNCOMPRESS = bind("blst_p1_uncompress", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle P1_FROM_AFFINE = bind("blst_p1_from_affine", null, ADDRESS, ADDRESS);
    private static final MethodHandle P1_TO_AFFINE = bind("blst_p1_to_affine", null, ADDRESS, ADDRESS);
    private static final MethodHandle P1_COMPRESS = bind("blst_p1_compress", null, ADDRESS, ADDRESS);
    private static final MethodHandle P1_ADD_OR_DOUBLE = bind("blst_p1_add_or_double", null, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle P1_CNEG = bind("blst_p1_cneg", null, ADDRESS, JAVA_BOOLEAN);
    private static final MethodHandle P1_MULT = bind("blst_p1_mult", null, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG);
    private static final MethodHandle P1_IS_EQUAL = bind("blst_p1_is_equal", JAVA_BOOLEAN, ADDRESS, ADDRESS);
    private static final MethodHandle P1_IS_INF = bind("blst_p1_is_inf", JAVA_BOOLEAN, ADDRESS);
    private static final MethodHandle P1_IN_G1 = bind("blst_p1_in_g1", JAVA_BOOLEAN, ADDRESS);
    private static final MethodHandle P1_GENERATOR = bind("blst_p1_generator", ADDRESS);

    private static final MethodHandle P2_UNCOMPRESS = bind("blst_p2_uncompress", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle P2_FROM_AFFINE = bind("blst_p2_from_affine", null, ADDRESS, ADDRESS);
    private static final MethodHandle P2_TO_AFFINE = bind("blst_p2_to_affine", null, ADDRESS, ADDRESS);
    private static final MethodHandle P2_COMPRESS = bind("blst_p2_compress", null, ADDRESS, ADDRESS);
    private static final MethodHandle P2_ADD_OR_DOUBLE = bind("blst_p2_add_or_double", null, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle P2_CNEG = bind("blst_p2_cneg", null, ADDRESS, JAVA_BOOLEAN);
    private static final MethodHandle P2_MULT = bind("blst_p2_mult", null, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG);
    private static final MethodHandle P2_IS_EQUAL = bind("blst_p2_is_equal", JAVA_BOOLEAN, ADDRESS, ADDRESS);
    private static final MethodHandle P2_IS_INF = bind("blst_p2_is_inf", JAVA_BOOLEAN, ADDRESS);
    private static final MethodHandle P2_IN_G2 = bind("blst_p2_in_g2", JAVA_BOOLEAN, ADDRESS);
    private static final MethodHandle P2_GENERATOR = bind("blst_p2_generator", ADDRESS);
    private static final MethodHandle HASH_TO_G2 = bind("blst_hash_to_g2", null, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG);

    private static final MethodHandle CORE_VERIFY_PK_IN_G1 = bind("blst_core_verify_pk_in_g1", JAVA_INT,
            ADDRESS, ADDRESS, JAVA_BOOLEAN, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG);
    private static final MethodHandle PAIRING_SIZEOF = bind("blst_pairing_sizeof", JAVA_LONG);
    private static final MethodHandle PAIRING_INIT = bind("blst_pairing_init", null, ADDRESS, JAVA_BOOLEAN, ADDRESS, JAVA_LONG);
    private static final MethodHandle PAIRING_AGGREGATE_PK_IN_G1 = bind("blst_pairing_aggregate_pk_in_g1", JAVA_INT,
            ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG);
    private static final MethodHandle PAIRING_COMMIT = bind("blst_pairing_commit", null, ADDRESS);
    private static final MethodHandle PAIRING_FINALVERIFY = bind("blst_pairing_finalverify", JAVA_BOOLEAN, ADDRESS, ADDRESS);
    private static final MethodHandle AGGREGATED_IN_G2 = bind("blst_aggregated_in_g2", null, ADDRESS, ADDRESS);

    private static final MethodHandle CHIA_DERIVE_CHILD_SK = bind("chia_bls_derive_child_sk", null, ADDRESS, ADDRESS, JAVA_INT);
    private static final MethodHandle CHIA_SCALAR_EQ = bind("chia_bls_scalar_eq", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle CHIA_ZEROIZE = bind("chia_bls_zeroize", null, ADDRESS, JAVA_LONG);

    static final long PAIRING_SIZE = pairingSizeof();

    private Blst() {
    }

    private static RuntimeException fail(Throwable t) {
        if (t instanceof RuntimeException re) {
            return re;
        }
        if (t instanceof Error e) {
            throw e;
        }
        return new IllegalStateException(t);
    }

    // --- scalars / secret keys ---

    static void keygenV3(MemorySegment outSk, MemorySegment ikm, long ikmLen) {
        try {
            KEYGEN_V3.invokeExact(outSk, ikm, ikmLen, MemorySegment.NULL, 0L);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean scalarFromBeBytes(MemorySegment out, MemorySegment in, long len) {
        try {
            return (boolean) SCALAR_FROM_BE_BYTES.invokeExact(out, in, len);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean skCheck(MemorySegment sk) {
        try {
            return (boolean) SK_CHECK.invokeExact(sk);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean skAddNCheck(MemorySegment out, MemorySegment a, MemorySegment b) {
        try {
            return (boolean) SK_ADD_N_CHECK.invokeExact(out, a, b);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void skToPkInG1(MemorySegment outPk, MemorySegment sk) {
        try {
            SK_TO_PK_IN_G1.invokeExact(outPk, sk);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void signPkInG1(MemorySegment outSig, MemorySegment hash, MemorySegment sk) {
        try {
            SIGN_PK_IN_G1.invokeExact(outSig, hash, sk);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    // --- G1 ---

    static int p1Uncompress(MemorySegment outAffine, MemorySegment in) {
        try {
            return (int) P1_UNCOMPRESS.invokeExact(outAffine, in);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p1FromAffine(MemorySegment out, MemorySegment in) {
        try {
            P1_FROM_AFFINE.invokeExact(out, in);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p1ToAffine(MemorySegment out, MemorySegment in) {
        try {
            P1_TO_AFFINE.invokeExact(out, in);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p1Compress(MemorySegment out, MemorySegment in) {
        try {
            P1_COMPRESS.invokeExact(out, in);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p1AddOrDouble(MemorySegment out, MemorySegment a, MemorySegment b) {
        try {
            P1_ADD_OR_DOUBLE.invokeExact(out, a, b);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p1Cneg(MemorySegment p, boolean cbit) {
        try {
            P1_CNEG.invokeExact(p, cbit);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p1Mult(MemorySegment out, MemorySegment p, MemorySegment scalar, long nbits) {
        try {
            P1_MULT.invokeExact(out, p, scalar, nbits);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean p1IsEqual(MemorySegment a, MemorySegment b) {
        try {
            return (boolean) P1_IS_EQUAL.invokeExact(a, b);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean p1IsInf(MemorySegment p) {
        try {
            return (boolean) P1_IS_INF.invokeExact(p);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean p1InG1(MemorySegment p) {
        try {
            return (boolean) P1_IN_G1.invokeExact(p);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    /** Returns blst's static generator; read-only, never write to it. */
    static MemorySegment p1Generator() {
        try {
            return ((MemorySegment) P1_GENERATOR.invokeExact()).reinterpret(P1_SIZE);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    // --- G2 ---

    static int p2Uncompress(MemorySegment outAffine, MemorySegment in) {
        try {
            return (int) P2_UNCOMPRESS.invokeExact(outAffine, in);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p2FromAffine(MemorySegment out, MemorySegment in) {
        try {
            P2_FROM_AFFINE.invokeExact(out, in);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p2ToAffine(MemorySegment out, MemorySegment in) {
        try {
            P2_TO_AFFINE.invokeExact(out, in);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p2Compress(MemorySegment out, MemorySegment in) {
        try {
            P2_COMPRESS.invokeExact(out, in);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p2AddOrDouble(MemorySegment out, MemorySegment a, MemorySegment b) {
        try {
            P2_ADD_OR_DOUBLE.invokeExact(out, a, b);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p2Cneg(MemorySegment p, boolean cbit) {
        try {
            P2_CNEG.invokeExact(p, cbit);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void p2Mult(MemorySegment out, MemorySegment p, MemorySegment scalar, long nbits) {
        try {
            P2_MULT.invokeExact(out, p, scalar, nbits);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean p2IsEqual(MemorySegment a, MemorySegment b) {
        try {
            return (boolean) P2_IS_EQUAL.invokeExact(a, b);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean p2IsInf(MemorySegment p) {
        try {
            return (boolean) P2_IS_INF.invokeExact(p);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean p2InG2(MemorySegment p) {
        try {
            return (boolean) P2_IN_G2.invokeExact(p);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    /** Returns blst's static generator; read-only, never write to it. */
    static MemorySegment p2Generator() {
        try {
            return ((MemorySegment) P2_GENERATOR.invokeExact()).reinterpret(P2_SIZE);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void hashToG2(MemorySegment out, MemorySegment msg, long msgLen, MemorySegment dst, long dstLen) {
        try {
            HASH_TO_G2.invokeExact(out, msg, msgLen, dst, dstLen, MemorySegment.NULL, 0L);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    // --- pairings ---

    static int coreVerifyPkInG1(MemorySegment pkAffine, MemorySegment sigAffine, MemorySegment msg, long msgLen,
                                MemorySegment dst, long dstLen) {
        try {
            return (int) CORE_VERIFY_PK_IN_G1.invokeExact(pkAffine, sigAffine, true, msg, msgLen, dst, dstLen,
                    MemorySegment.NULL, 0L);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    private static long pairingSizeof() {
        try {
            return (long) PAIRING_SIZEOF.invokeExact();
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    /** The context keeps a pointer to {@code dst}; it must outlive the context. */
    static void pairingInit(MemorySegment ctx, MemorySegment dst, long dstLen) {
        try {
            PAIRING_INIT.invokeExact(ctx, true, dst, dstLen);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static int pairingAggregatePkInG1(MemorySegment ctx, MemorySegment pkAffine, MemorySegment msg, long msgLen) {
        try {
            return (int) PAIRING_AGGREGATE_PK_IN_G1.invokeExact(ctx, pkAffine, MemorySegment.NULL, msg, msgLen,
                    MemorySegment.NULL, 0L);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void pairingCommit(MemorySegment ctx) {
        try {
            PAIRING_COMMIT.invokeExact(ctx);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean pairingFinalVerify(MemorySegment ctx, MemorySegment gtSig) {
        try {
            return (boolean) PAIRING_FINALVERIFY.invokeExact(ctx, gtSig);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void aggregatedInG2(MemorySegment outFp12, MemorySegment sigAffine) {
        try {
            AGGREGATED_IN_G2.invokeExact(outFp12, sigAffine);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    // --- chia_bls shim ---

    /** Chia's hardened (EIP-2333 Lamport + KeyGen v3) child key derivation. */
    static void chiaDeriveChildSk(MemorySegment outSk, MemorySegment parentSk, int index) {
        try {
            CHIA_DERIVE_CHILD_SK.invokeExact(outSk, parentSk, index);
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static boolean chiaScalarEq(MemorySegment a, MemorySegment b) {
        try {
            return (int) CHIA_SCALAR_EQ.invokeExact(a, b) != 0;
        } catch (Throwable t) {
            throw fail(t);
        }
    }

    static void zeroize(MemorySegment segment) {
        try {
            CHIA_ZEROIZE.invokeExact(segment, segment.byteSize());
        } catch (Throwable t) {
            throw fail(t);
        }
    }
}
