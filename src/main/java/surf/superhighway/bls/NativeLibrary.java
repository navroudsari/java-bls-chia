package surf.superhighway.bls;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Locale;

/**
 * Locates and loads the bundled native library (blst plus the chia_bls shim).
 *
 * <p>The library for the current platform is read from the classpath at
 * {@code /native/<os>-<arch>/}. Set the system property {@value #PATH_PROPERTY}
 * to load a library from an explicit path instead, e.g. one you built yourself.
 */
final class NativeLibrary {

    static final String PATH_PROPERTY = "surf.superhighway.bls.library.path";

    static final String OS;
    static final String ARCH;
    static final SymbolLookup LOOKUP;

    static {
        OS = detectOs();
        ARCH = detectArch();
        LOOKUP = load();
    }

    private NativeLibrary() {
    }

    private static SymbolLookup load() {
        String override = System.getProperty(PATH_PROPERTY);
        if (override != null && !override.isEmpty()) {
            return SymbolLookup.libraryLookup(Path.of(override), Arena.global());
        }

        String fileName = switch (OS) {
            case "linux" -> "libchiabls.so";
            case "macos" -> "libchiabls.dylib";
            case "windows" -> "chiabls.dll";
            default -> throw new UnsatisfiedLinkError("Unsupported OS: " + OS);
        };
        String resource = "/native/" + OS + "-" + ARCH + "/" + fileName;

        try (InputStream in = NativeLibrary.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new UnsatisfiedLinkError("No native library bundled for " + OS + "-" + ARCH
                        + " (expected classpath resource " + resource + "); set -D" + PATH_PROPERTY);
            }

            Path dir = OS.equals("windows")
                    ? Files.createTempDirectory("chiabls")
                    : Files.createTempDirectory("chiabls", PosixFilePermissions.asFileAttribute(
                            PosixFilePermissions.fromString("rwx------")));
            Path file = dir.resolve(fileName);
            Files.copy(in, file, StandardCopyOption.REPLACE_EXISTING);

            SymbolLookup lookup = SymbolLookup.libraryLookup(file, Arena.global());

            // A loaded library can be unlinked on POSIX systems; Windows keeps it locked until exit.
            if (OS.equals("windows")) {
                file.toFile().deleteOnExit();
                dir.toFile().deleteOnExit();
            } else {
                Files.deleteIfExists(file);
                Files.deleteIfExists(dir);
            }
            return lookup;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to extract native library " + resource, e);
        }
    }

    private static String detectOs() {
        String name = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        if (name.startsWith("linux")) {
            return "linux";
        }
        if (name.startsWith("mac") || name.startsWith("darwin")) {
            return "macos";
        }
        if (name.startsWith("windows")) {
            return "windows";
        }
        return name;
    }

    private static String detectArch() {
        String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
        return switch (arch) {
            case "amd64", "x86_64" -> "x86_64";
            case "aarch64", "arm64" -> "aarch64";
            default -> arch;
        };
    }
}
