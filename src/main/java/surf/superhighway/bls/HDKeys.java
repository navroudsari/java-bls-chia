package surf.superhighway.bls;

import java.util.Objects;

/**
 * Chia wallet derivation paths, matching chia-bls {@code derive_keys.rs}.
 *
 * <p>Indices are {@code long} values in [0, 4294967295] (Rust {@code u32}); anything outside that
 * range throws {@link IllegalArgumentException}.
 *
 * <p>Single-step derivation lives on the key types: {@link PrivateKey#deriveHardened},
 * {@link PrivateKey#deriveUnhardened}, {@link PublicKey#deriveUnhardened} and
 * {@link Signature#deriveUnhardened}. Intermediate private keys created along a path are
 * destroyed before these methods return.
 */
public final class HDKeys {

    private static final long PURPOSE = 12381;
    private static final long CHIA = 8444;
    private static final long WALLET = 2;
    private static final long POOL_SINGLETON = 5;
    private static final long POOL_AUTHENTICATION = 6;

    private HDKeys() {
    }

    public static PrivateKey masterToWalletHardenedIntermediate(PrivateKey master) {
        return deriveHardened(master, PURPOSE, CHIA, WALLET);
    }

    public static PrivateKey masterToWalletHardened(PrivateKey master, long index) {
        return deriveHardened(master, PURPOSE, CHIA, WALLET, index);
    }

    public static PrivateKey masterToWalletUnhardenedIntermediate(PrivateKey master) {
        return deriveUnhardened(master, PURPOSE, CHIA, WALLET);
    }

    public static PrivateKey masterToWalletUnhardened(PrivateKey master, long index) {
        return deriveUnhardened(master, PURPOSE, CHIA, WALLET, index);
    }

    public static PublicKey masterToWalletUnhardenedIntermediate(PublicKey master) {
        return deriveUnhardened(master, PURPOSE, CHIA, WALLET);
    }

    public static PublicKey masterToWalletUnhardened(PublicKey master, long index) {
        return deriveUnhardened(master, PURPOSE, CHIA, WALLET, index);
    }

    public static PrivateKey masterToPoolSingleton(PrivateKey master, long poolWalletIndex) {
        return deriveHardened(master, PURPOSE, CHIA, POOL_SINGLETON, poolWalletIndex);
    }

    /**
     * @throws IllegalArgumentException if either index is not in [0, 10000)
     */
    public static PrivateKey masterToPoolAuthentication(PrivateKey master, long poolWalletIndex, long index) {
        if (poolWalletIndex < 0 || poolWalletIndex >= 10000 || index < 0 || index >= 10000) {
            throw new IllegalArgumentException("poolWalletIndex and index must be in [0, 10000)");
        }
        return deriveHardened(master, PURPOSE, CHIA, POOL_AUTHENTICATION, poolWalletIndex * 10000 + index);
    }

    /** Follows a hardened path, destroying each intermediate key. */
    public static PrivateKey deriveHardened(PrivateKey key, long... path) {
        Objects.requireNonNull(key, "key");
        PrivateKey current = key;
        for (long index : path) {
            PrivateKey next = current.deriveHardened(index);
            if (current != key) {
                current.destroy();
            }
            current = next;
        }
        return current == key ? key.copy() : current;
    }

    /** Follows an unhardened path, destroying each intermediate key. */
    public static PrivateKey deriveUnhardened(PrivateKey key, long... path) {
        Objects.requireNonNull(key, "key");
        PrivateKey current = key;
        for (long index : path) {
            PrivateKey next = current.deriveUnhardened(index);
            if (current != key) {
                current.destroy();
            }
            current = next;
        }
        return current == key ? key.copy() : current;
    }

    public static PublicKey deriveUnhardened(PublicKey key, long... path) {
        Objects.requireNonNull(key, "key");
        PublicKey current = key;
        for (long index : path) {
            current = current.deriveUnhardened(index);
        }
        return current;
    }
}
