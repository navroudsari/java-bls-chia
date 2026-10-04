/*
 * Native support library for java-bls-chia.
 *
 * Compiles blst as a single translation unit and adds the one primitive blst
 * does not export in the form Chia needs: hardened child key derivation.
 *
 * Chia's HDKeys::DeriveChildSk (C++) and SecretKey::derive_hardened (Rust)
 * compute EIP-2333's compressed Lamport public key and feed it to KeyGen
 * from draft-irtf-cfrg-bls-signature-03 (blst_keygen_v3). blst's own
 * blst_derive_child_eip2333 uses the later KeyGen (version 4), which yields
 * different keys. Reusing blst's Lamport implementation here keeps every
 * intermediate secret in native memory, where blst scrubs it before returning.
 */

#include "server.c"

#if defined(_WIN32)
# define CHIA_BLS_EXPORT __declspec(dllexport)
#else
# define CHIA_BLS_EXPORT __attribute__((visibility("default")))
#endif

CHIA_BLS_EXPORT
void chia_bls_derive_child_sk(pow256 SK, const pow256 parent_SK,
                              unsigned int child_index)
{
    parent_SK_to_lamport_PK(SK, parent_SK, child_index);
    keygen(SK, SK, sizeof(pow256), NULL, 0, NULL, 0, 3);
}

/* Constant-time comparison of two secret scalars. Returns 1 if equal. */
CHIA_BLS_EXPORT
int chia_bls_scalar_eq(const pow256 a, const pow256 b)
{
    return (int)vec_is_equal(a, b, sizeof(pow256));
}

/*
 * Overwrite secret memory in a way the compiler cannot elide. Byte-wise,
 * unlike vec_zero, so any length and alignment is wiped completely.
 */
CHIA_BLS_EXPORT
void chia_bls_zeroize(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;

    while (len--)
        *p++ = 0;

#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}
