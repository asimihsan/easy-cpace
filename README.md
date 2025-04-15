# EasyCPace

**EasyCPace** is a lightweight C library implementing the **CPace** protocol, specifically the **`CPace-X25519-SHA512`** variant as described in [`draft-irtf-cfrg-cpace-13`](./docs/draft-irtf-cfrg-cpace-13.txt).

## Introduction

**Password-Authenticated Key Exchange (PAKE)** protocols allow two parties who share a low-entropy secret (like a password) to establish a strong, high-entropy shared cryptographic key over an insecure channel, without revealing the password itself. This derived key can then be used for secure communication (e.g., encryption, authentication).

**CPace** is a balanced PAKE protocol, meaning both parties perform similar computations. It is designed to be efficient and secure against various attacks common in password-based authentication scenarios.

**EasyCPace** aims to provide:

* A **simple and easy-to-use API** for the CPace protocol exchange.
* An implementation in portable **C99**.
* Minimal external dependencies, using **Monocypher** as the cryptographic backend (fetched automatically via CMake).
* Suitability for resource-constrained environments, including **embedded systems**, by facilitating static or stack-based memory allocation for contexts.

## Features

* Implements **CPace-X25519-SHA512** based on `draft-irtf-cfrg-cpace-13`.
* Uses the excellent [Monocypher](https://monocypher.org/) library for cryptographic primitives (X25519, SHA-512, constant-time operations).
* Dependency on Monocypher managed automatically via CMake's `WorkspaceContent`.
* Simple 3-step API: `_start`, `_respond`, `_finish`.
* Context structure (`cpace_ctx_t`) exposed for **static/stack allocation**, avoiding dynamic memory allocation in the core protocol flow.
* Written in standard C99.
* CMake build system integration.
* Includes usage examples (`basic_exchange.c`, `cpace_embedded_example.c`).
* Unit tests using the Unity framework (`test_cpace_api.c`, `test_cpace_vectors.c`).
* Test vectors generated from the IETF draft specification.
* Comprehensive sanitizer support (ASan, UBSan, TSan, MSan) for memory and behavior analysis.

## Getting Started

This project uses `just` (a command runner) for convenience. Ensure `just`, `cmake`, and a C compiler (like GCC or Clang) are installed.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your_username/cpace.git](https://github.com/your_username/cpace.git) # TODO: Replace with actual repo path
    cd cpace
    ```

2.  **Build the library and examples:**
    ```bash
    just build
    ```
    This command runs CMake configuration and builds the targets in the `build/` directory.

3.  **Run the basic example:**
    ```bash
    just run-example basic_exchange
    # or
    ./build/examples/basic_exchange
    ```
    This will execute a simulated CPace exchange between an initiator and responder, printing the derived keys.

4.  **Run tests:**
    ```bash
    just test
    # or
    cd build && ctest && cd ..
    ```

## Building Manually (CMake)

If you prefer not to use `just`, you can use CMake directly:

1.  **Configure the project:**
    ```bash
    # Create a build directory
    cmake -B build -S .

    # Optional: Configure build options (defaults are usually ON)
    # cmake -B build -S . -DCPACE_BUILD_TESTS=OFF -DCPACE_BUILD_EXAMPLES=OFF
    # cmake -B build -S . -DCPACE_ENABLE_DEBUG_LOGGING=ON # Enable verbose debug prints
    
    # Build with sanitizers
    # cmake -B build-asan -S . -DCPACE_ENABLE_ASAN=ON     # AddressSanitizer
    # cmake -B build-ubsan -S . -DCPACE_ENABLE_UBSAN=ON   # UndefinedBehaviorSanitizer
    # cmake -B build-tsan -S . -DCPACE_ENABLE_TSAN=ON     # ThreadSanitizer
    # cmake -B build-msan -S . -DCPACE_ENABLE_MSAN=ON -DCMAKE_C_COMPILER=clang # MemorySanitizer (requires Clang)
    ```

2.  **Build the targets:**
    ```bash
    cmake --build build
    
    # Or for sanitizer builds:
    # cmake --build build-asan
    ```

3.  **Run examples/tests (from the project root):**
    ```bash
    ./build/examples/basic_exchange
    ./build/examples/cpace_embedded_example
    # Run tests using CTest
    cd build
    ctest --output-on-failure
    cd ..
    
    # Run tests with sanitizers
    # cd build-asan
    # ctest --output-on-failure
    # cd ..
    ```

4. **Run sanitizer tests:**
   ```bash
   # Using just targets (recommended)
   just sanitizers
   
   # Or for specific sanitizers
   just sanitizers-asan
   just sanitizers-ubsan
   ```

For more detailed information on using sanitizers, see the [sanitizers documentation](docs/sanitizers.md).

## Usage Example

Here's a simplified overview of a CPace exchange using EasyCPace:

```c
#include <easy_cpace.h>
#include <stdio.h>
#include <string.h> // For memcmp
#include <stdlib.h> // For EXIT_SUCCESS/FAILURE

int main() {
    // 1. Initialize Monocypher Backend
    if (easy_cpace_monocypher_init() != CPACE_OK) {
        fprintf(stderr, "Failed to init Monocypher backend\n");
        return EXIT_FAILURE;
    }

    // 2. Get Crypto Provider
    const crypto_provider_t *provider = cpace_get_provider_monocypher();
    if (!provider) {
        fprintf(stderr, "Failed to get Monocypher provider\n");
        easy_cpace_monocypher_cleanup();
        return EXIT_FAILURE;
    }

    // 3. Define Shared Inputs
    const uint8_t prs[] = "secret_password"; // Password Related String
    const size_t prs_len = sizeof(prs) - 1;
    const uint8_t sid[] = {0x01, 0x02, 0x03, 0x04}; // Session ID (MUST be unique per session)
    const size_t sid_len = sizeof(sid);
    const uint8_t ci[] = "channel_id";           // Channel ID (optional context)
    const size_t ci_len = sizeof(ci) - 1;
    const uint8_t ad[] = {0xAA, 0xBB};           // Associated Data (optional context)
    const size_t ad_len = sizeof(ad);

    // 4. Prepare Contexts and Buffers (Stack Allocation)
    cpace_ctx_t ctx_i, ctx_r;                 // Contexts for Initiator and Responder
    uint8_t msg1[CPACE_PUBLIC_BYTES];         // Initiator -> Responder message (Ya)
    uint8_t msg2[CPACE_PUBLIC_BYTES];         // Responder -> Initiator message (Yb)
    uint8_t isk_i[CPACE_ISK_BYTES];           // Initiator's derived key
    uint8_t isk_r[CPACE_ISK_BYTES];           // Responder's derived key
    cpace_error_t err = CPACE_OK;

    // 5. Initialize Contexts
    err = cpace_ctx_init(&ctx_i, CPACE_ROLE_INITIATOR, provider);
    if (err != CPACE_OK) { /* handle error */ }
    err = cpace_ctx_init(&ctx_r, CPACE_ROLE_RESPONDER, provider);
    if (err != CPACE_OK) { /* handle error */ }

    // --- Protocol Exchange ---

    // 6. Initiator Starts -> Generates msg1 (Ya)
    err = cpace_initiator_start(&ctx_i, prs, prs_len, sid, sid_len, ci, ci_len, ad, ad_len, msg1);
    if (err != CPACE_OK) { /* handle error, cleanup */ }
    printf("Initiator sent msg1 (Ya)\n");

    // [Network: msg1 sent from Initiator to Responder]

    // 7. Responder Responds -> Processes msg1, Generates msg2 (Yb) and ISK
    err = cpace_responder_respond(&ctx_r, prs, prs_len, sid, sid_len, ci, ci_len, ad, ad_len, msg1, msg2, isk_r);
    if (err != CPACE_OK) { /* handle error, cleanup */ }
    printf("Responder sent msg2 (Yb) and derived ISK\n");

    // [Network: msg2 sent from Responder to Initiator]

    // 8. Initiator Finishes -> Processes msg2, Derives ISK
    err = cpace_initiator_finish(&ctx_i, msg2, isk_i);
    if (err != CPACE_OK) { /* handle error, cleanup */ }
    printf("Initiator derived ISK\n");

    // --- Verification & Cleanup ---

    // 9. Verify Keys Match
    if (memcmp(isk_i, isk_r, CPACE_ISK_BYTES) == 0) {
        printf("SUCCESS: Derived keys match!\n");
        // Use isk_i or isk_r for subsequent cryptographic operations
    } else {
        fprintf(stderr, "FAILURE: Derived keys do NOT match!\n");
    }

    // 10. Cleanup Contexts (Crucial: Zeroizes sensitive data)
    cpace_ctx_cleanup(&ctx_i);
    cpace_ctx_cleanup(&ctx_r);

    // 11. Cleanup Backend
    easy_cpace_monocypher_cleanup();

    return (memcmp(isk_i, isk_r, CPACE_ISK_BYTES) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
```

## API Overview

The main public API is defined in `include/easy_cpace.h`:

**Backend Management:**

* `easy_cpace_monocypher_init()`: Initializes the Monocypher backend (currently a no-op, but required for future compatibility).
* `easy_cpace_monocypher_cleanup()`: Cleans up the Monocypher backend (currently a no-op).
* `cpace_get_provider_monocypher()`: Returns a pointer to the `crypto_provider_t` structure containing function pointers for Monocypher's cryptographic operations.

**Context Management:**

* `cpace_ctx_init(cpace_ctx_t *ctx, cpace_role_t role, const crypto_provider_t *provider)`: Initializes a user-allocated `cpace_ctx_t` structure for either an `INITIATOR` or `RESPONDER`.
* `cpace_ctx_cleanup(cpace_ctx_t *ctx)`: Securely cleanses (zeroizes) sensitive data within the context (ephemeral keys, shared secrets, etc.). **Must be called** when the context is no longer needed or after an error.

**Protocol Steps:**

* `cpace_initiator_start(...)`: **Step 1 (Initiator)**. Generates the first message (`msg1_out` / Ya) based on the shared password (`prs`) and session parameters (`sid`, `ci`, `ad`).
* `cpace_responder_respond(...)`: **Step 2 (Responder)**. Processes the initiator's message (`msg1_in`), generates the second message (`msg2_out` / Yb), and derives the final shared key (`isk_out`).
* `cpace_initiator_finish(...)`: **Step 3 (Initiator)**. Processes the responder's message (`msg2_in`) and derives the final shared key (`isk_out`).

**Constants and Types:**

* `CPACE_PUBLIC_BYTES`: Size of exchanged messages (Ya/Yb).
* `CPACE_ISK_BYTES`: Size of the derived Implicit Shared Key (ISK).
* `CPACE_MAX_SID_LEN`, `CPACE_MAX_CI_LEN`, `CPACE_MAX_AD_LEN`: Maximum lengths for input parameters when using the stack-allocated context.
* `cpace_role_t`: Enum for `CPACE_ROLE_INITIATOR` or `CPACE_ROLE_RESPONDER`.
* `cpace_error_t`: Enum for error codes (e.g., `CPACE_OK`, `CPACE_ERROR`, `CPACE_ERROR_INVALID_ARGUMENT`).
* `cpace_ctx_t`: The protocol context structure (exposed for static allocation).

## Security Considerations

Using cryptography correctly is crucial. Please consider the following:

* **General Crypto:** Familiarize yourself with cryptographic best practices. Consider resources like [Crypto 101](https://www.crypto101.io/).
* **Password (`prs`):** This is the shared secret. Its strength is paramount. EasyCPace derives a strong key *from* the password, but it cannot make a weak password strong. Ensure passwords meet the security requirements of your application.
* **Session ID (`sid`):** This parameter **MUST be unique for every CPace exchange**. Using the same SID allows attackers to replay messages or interfere with sessions. A cryptographically secure random value generated for each session is highly recommended.
* **Channel ID (`ci`):** This provides domain separation. Use distinct `ci` values if the same password might be used across different protocols or application contexts to prevent cross-protocol attacks.
* **Associated Data (`ad`):** This data is authenticated along with the key exchange but is **not encrypted**. Both parties must provide the *exact same* `ad` for the exchange to succeed. It can be used to bind the session key to specific context information (e.g., usernames, connection identifiers).
* **Context Cleanup:** **Always call `cpace_ctx_cleanup()`** on the context structure after the exchange is complete (success or failure) or when it's no longer needed. This function securely wipes ephemeral keys and intermediate secrets stored within the context. Failure to do so could expose sensitive material.
* **Backend Security (Monocypher):** EasyCPace relies on Monocypher for its cryptographic operations. Monocypher is designed with security and simplicity in mind, including constant-time operations where necessary. Refer to the [Monocypher documentation](https://monocypher.org/manual/) for its specific security considerations.
* **Draft Compliance:** This library implements `draft-irtf-cfrg-cpace-13`. Be aware of potential changes in future drafts or the final RFC.

## Dependencies

* **CMake** (Version 3.27 or later recommended)
* **C Compiler** (Supporting C99, e.g., GCC, Clang)
* **Monocypher** (Version 4.0.2 - automatically fetched by CMake)
* **Python 3** (Required only for running the test vector generation script when building tests)
* **Just** (Optional, for convenient build/test commands)

## Testing

The library includes unit tests using the [Unity](https://github.com/ThrowTheSwitch/Unity) framework.

* **API Tests (`test_cpace_api.c`):** Test the core API functions and state transitions.
* **Vector Tests (`test_cpace_vectors.c`):** Test the implementation against the official test vectors provided in the IETF draft. The vectors are parsed from the draft text and converted into a C header (`generated_rfc_vectors.h`) by the Python script (`scripts/generate_test_vectors.py`) during the build process.

To run tests:

```bash
# Using just
just test

# Using CTest (after configuring and building in 'build/')
cd build
ctest --output-on-failure
cd ..
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests. (TODO: Add more specific contribution guidelines if desired).

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0). See the [LICENSE](LICENSE) file for details.
