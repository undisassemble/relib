# ReLib

> [!WARNING]
> ReLib is currently unstable and being tested, don't try to use this on any malicious files.

Library for analyzing x86_64 PEs.


## Usage

To include it in your project use CMake's `add_subdirectory`.

CMake options:
- `RELIB_SHARED`: `ON` builds shared (.dll) libraries, `OFF` builds static (.lib) libraries.
- `RELIB_DEBUG`: Whether the debug version should be built, automatically enabled if `CMAKE_BUILD_TYPE` is `Debug`.


## License

ReLib is licensed under the MIT License.

