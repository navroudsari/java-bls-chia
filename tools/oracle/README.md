# Oracle vectors

Test vectors in `src/test/resources/oracle/` come from Chia's C++ library (bls-signatures), the
reference for the parts of this library that chia-bls (Rust) does not implement.

- `g2_unhardened.csv`: `oracle.cpp`, compiled against bls-signatures' `src/` and the blst
  submodule. `HDKeys::DeriveChildG2Unhardened` is not exposed to Python, so it is called directly.

  ```shell
  sh ../../native/blst/build.sh           # produces libblst.a
  g++ -std=c++17 -I <bls-signatures>/src -I ../../native/blst oracle.cpp \
      <bls-signatures>/src/{elements,privatekey,schemes,bls}.cpp libblst.a -o oracle
  ./oracle
  ```

- `schemes.csv`: `gen_blspy.py`, run with `pip install blspy==2.0.3` (Python bindings to the C++
  library). Covers the basic and proof-of-possession schemes.
