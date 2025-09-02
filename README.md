# WGU Capstone: Post-Quantum Cryptography Performance on HSMs

This repository contains the source code and supporting documentation for a Bachelor of Science in Cybersecurity and Information Assurance capstone project for Western Governors University (WGU).

The project implements and benchmarks NIST-standardized Post-Quantum Cryptography (PQC) algorithms against classical algorithms on a production Hardware Security Module (HSM) to provide empirical data for enterprise migration planning.

---

## Project Overview

### Problem Statement

The rise of quantum computing threatens to compromise the classical cryptographic algorithms (such as RSA and ECC) that secure modern digital infrastructure. While NIST has standardized new quantum-resistant algorithms like CRYSTALS-Dilithium (ML-DSA), enterprises lack empirical data on how these new algorithms perform on their existing HSM hardware. This knowledge gap makes it difficult to plan for migration, creating a significant security risk.

### Solution

This project addresses that gap by:
1.  Implementing both classical and post-quantum signature algorithms in C++ using the PKCS#11 standard.
2.  Executing comprehensive performance benchmarks on an nCipher (Entrust) nShield HSM.
3.  Developing a "hash-then-sign" architecture to overcome HSM memory limitations for large file signing.
4.  Creating a proof-of-concept PQC code-signing application.
5.  Analyzing the results to provide actionable guidance for enterprise migration strategies.

---

## Repository Contents

This repository includes the C++ source code for the benchmarking and demonstration tools, along with the final capstone report.

### Source Code

*   `classical_algorithm_benchmark.cpp`: A tool to measure the performance (key generation, signing, verification) of classical algorithms: RSA (2048/4096), ECC (P-256/P-384/P-521), and DSA (2048/3072).
*   `mldsa_hash_sign.cpp`: A tool to measure the performance of the post-quantum algorithm ML-DSA (parameter sets 44, 65, 87) using the "hash-then-sign" method.
*   `mldsa_code_signer.cpp`: A proof-of-concept application that demonstrates how to sign a file (e.g., a DLL) with an ML-DSA signature and embed the signature into the file for verification.
*   `create_mock_dll.cpp`: A utility to generate a sample binary file used as a target for the code signing application.
*   `*.txt`: Output logs from benchmark and code signing runs, used as data for the final report.

---

## Prerequisites and Building

### Prerequisites

*   **Hardware**: An nCipher (Entrust) nShield HSM.
*   **Software**:
    *   Windows Operating System (developed on Windows 11).
    *   nShield Security World Software (v13.9 or similar).
    *   A C++ compiler, such as the one included with Visual Studio.
*   **Configuration**:
    *   The HSM must be configured with a Security World and an operational slot (hardware, carset, or softcard).
    *   The PKCS#11 library (`cknfast.dll`) must be accessible.
    *   For the DSA benchmarks, keys with the labels `dsa2048` and `dsa3072` must exist on the HSM.

### Building the Tools

The applications can be compiled from the command line using a developer environment like the x64 Native Tools Command Prompt for Visual Studio. You must link against the nCipher PKCS#11 library.

**Example Compile Command:**
```powershell
# Ensure you are in the directory with the source files
# The path to cknfast.lib may vary based on your installation
cl.exe /EHsc /I "C:\Program Files\nCipher\nfast\toolkits\pkcs11" classical_algorithm_benchmark.cpp /link "C:\Program Files\nCipher\nfast\toolkits\pkcs11\cknfast.lib"
```
Repeat this command for each `.cpp` file you wish to build.

---

## Key Findings and Performance Results

This project generated statistically significant performance data that proves PQC algorithms are viable for enterprise use.

### Major Discoveries

1.  **HSM Limitation**: The nShield HSM has a ~200KB limit for direct signing operations.
2.  **"Hash-Then-Sign" is Essential**: To sign files larger than 200KB, a "hash-then-sign" approach is required. In this architecture, the client application computes a SHA-256 hash of the file and sends only the 32-byte hash to the HSM for signing. This is a standard and secure practice that completely bypasses the size limitation.
3.  **PQC is Faster than RSA/ECC**: For signing and verification operations, ML-DSA is significantly faster than RSA and ECC, making it an excellent candidate for migration.

### Performance Summary (1MB File)

| Algorithm | Key Gen (ms) | Sign (ms) | Verify (ms) | Signature Size (bytes) | Quantum Safe |
| :---------- | :----------- | :-------- | :---------- | :--------------------- | :----------- |
| **DSA-2048** | N/A | **4.3** | 6.5 | 56 | No |
| **ECC-P256** | 21.8 | 158.6 | 151.9 | 64 | No |
| **RSA-2048** | 320.7 | 163.4 | 155.6 | 256 | No |
| **ML-DSA-44** | 33.8 | **9.1** | **3.6** | 2420 | **Yes** |

### Migration Recommendation

The research concludes that a **hybrid migration strategy** is the most prudent approach. This involves creating composite signatures containing both a classical (e.g., RSA) and a post-quantum (ML-DSA) signature. This provides defense-in-depth and ensures backward compatibility while the enterprise gradually transitions all systems to be PQC-aware.
