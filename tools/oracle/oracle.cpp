// Oracle: Chia's C++ HDKeys::DeriveChildG2Unhardened, built against the same blst.
#include "bls.hpp"
#include <cstdio>
using namespace bls;

int main() {
    const uint32_t indices[] = {0u, 1u, 42u, 0x7fffffffu, 0x80000000u, 0xffffffffu};
    PrivateKey master = PrivateKey::FromByteVector(
        Util::HexToBytes("52d75c4707e39595b27314547f9723e5530c01198af3fc5849d9a7af65631efb"));
    for (uint32_t k = 0; k < 3; k++) {
        PrivateKey sk = HDKeys::DeriveChildSkUnhardened(master, k);
        std::vector<uint8_t> msg = {1, 2, 3, (uint8_t)k};
        G2Element sig = AugSchemeMPL().Sign(sk, msg);
        for (uint32_t idx : indices) {
            printf("%s,%u,%s\n", Util::HexStr(sig.Serialize()).c_str(), idx,
                   Util::HexStr(HDKeys::DeriveChildG2Unhardened(sig, idx).Serialize()).c_str());
        }
    }
    G2Element inf;
    printf("%s,%u,%s\n", Util::HexStr(inf.Serialize()).c_str(), 7u,
           Util::HexStr(HDKeys::DeriveChildG2Unhardened(inf, 7).Serialize()).c_str());
    return 0;
}
