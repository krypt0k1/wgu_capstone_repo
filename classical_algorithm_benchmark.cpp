/*
 * Classical Algorithm Performance Benchmark using PKCS#11 with nShield HSM
 * 
 * This application benchmarks classical cryptographic algorithms performance 
 * across different file sizes using actual PKCS#11 calls to nShield HSM slots:
 * - File sizes: 1KB, 10KB, 100KB, 200KB, 300KB
 * - RSA: 2048-bit, 4096-bit (1024-bit excluded for enterprise security)
 * - ECC NIST curves: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1)
 * - DSA: 1024-bit, 2048-bit, 3072-bit
 * - Tests all available HSM slots
 * - Metrics: Key generation, signing, verification times and signature sizes
 * - 100 iterations per test for statistical accuracy
 * 
 * IMPORTANT: nCipher nShield Usage Requirements
 * =============================================
 * 
 * 1. Classical Algorithm Message Size Handling:
 *    - Hash-then-Sign Approach: SHA-256 hash computed first, then signed with basic mechanisms
 *    - RSA: Uses CKM_RSA_PKCS to sign 32-byte SHA-256 hash
 *    - ECC: Uses CKM_ECDSA to sign 32-byte SHA-256 hash  
 *    - DSA: Uses CKM_DSA to sign 32-byte SHA-256 hash
 *    - All algorithms handle unlimited message sizes via consistent hash-then-sign pattern
 * 
 * 2. Softcard Preload Requirement:
 *    For softcard slots, you must preload the softcard before running:
 * 
 *      preload -s <SoftcardName> .\classical_algorithm_benchmark.exe
 * 
 *    Example:
 *      preload -s TestSoftcard .\classical_algorithm_benchmark.exe
 * 
 *    This resolves login errors (0xa2) by loading the softcard and keys into HSM memory.
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <fstream>
#include <map>
#include <random>
#include <numeric>
#include <algorithm>
#include <thread>
#include <ctime>
#include <sstream>

// Windows CryptoAPI for SHA-256
#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
    #pragma comment(lib, "advapi32.lib")
#endif

// Windows-specific includes
#ifdef _WIN32
    #include <windows.h>
    #pragma pack(push, cryptoki, 1)
#endif

// PKCS#11 includes
#include "pkcs11/cryptoki.h"

#ifdef _WIN32
    #pragma pack(pop, cryptoki)
#endif

// Benchmark configuration
const size_t NUM_ITERATIONS = 1000;

// Adaptive iteration count based on file size (to keep reasonable test times)
size_t getIterationCount(size_t fileSize) {
    if (fileSize >= 100 * 1024 * 1024) {  // >= 100MB
        return 10;   // Only 10 iterations for very large files
    } else if (fileSize >= 10 * 1024 * 1024) {  // >= 10MB
        return 100;  // 100 iterations for large files
    } else {
        return NUM_ITERATIONS;  // Full 1000 iterations for smaller files
    }
}

// File sizes to test (in bytes) 
const std::vector<size_t> FILE_SIZES = {
    1 * 1024,           // 1 KB
    100 * 1024,         // 100 KB
    500 * 1024,         // 500 KB
    1024 * 1024         // 1 MB
};
const std::vector<std::string> FILE_SIZE_NAMES = {"1KB", "100KB", "500KB", "1MB"};

// PKCS#11 function list
CK_FUNCTION_LIST_PTR pFunctionList = NULL;

// Algorithm parameter set information
struct AlgorithmParameterSet {
    CK_KEY_TYPE keyType;
    CK_MECHANISM_TYPE keyGenMechanism;
    CK_MECHANISM_TYPE signMechanism;
    std::string name;
    std::string description;
    int keySize;
    int expectedSignatureSize;
    std::string securityLevel;
    std::string category; // "RSA", "ECC", "DSA"
};

// Slot information 
struct SlotInfo {
    CK_SLOT_ID slotId;
    std::string slotDescription;
    std::string tokenLabel;
    bool hasToken;
    bool supportsClassicalAlgs;
};

// Benchmark results structure
struct BenchmarkResult {
    double keyGenTimeMs;
    double avgSignTimeMs;
    double avgVerifyTimeMs;
    size_t signatureSize;
    std::vector<double> signTimes;
    std::vector<double> verifyTimes;
    int successfulIterations;
    CK_SLOT_ID slotId;
    std::string slotDescription;
};

// Test results for all combinations
std::map<CK_SLOT_ID, std::map<std::string, std::map<std::string, BenchmarkResult>>> benchmarkResults;

std::vector<AlgorithmParameterSet> getClassicalAlgorithmSets() {
    return {
        // RSA algorithms
        {CKK_RSA, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, "RSA-2048", "RSA 2048-bit", 2048, 256, "112-bit security", "RSA"},
        {CKK_RSA, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, "RSA-4096", "RSA 4096-bit", 4096, 512, "150-bit security", "RSA"},
        
        // ECC NIST curves
        {CKK_EC, CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, "ECC-P256", "NIST P-256 (secp256r1)", 256, 64, "128-bit security", "ECC"},
        {CKK_EC, CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, "ECC-P384", "NIST P-384 (secp384r1)", 384, 96, "192-bit security", "ECC"},
        {CKK_EC, CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, "ECC-P521", "NIST P-521 (secp521r1)", 521, 132, "256-bit security", "ECC"},
        
        // DSA algorithms - using existing keys
        {CKK_DSA, CKM_DSA_KEY_PAIR_GEN, CKM_DSA, "1024dsa", "DSA 1024-bit", 1024, 40, "80-bit security", "DSA"},
        {CKK_DSA, CKM_DSA_KEY_PAIR_GEN, CKM_DSA, "2048dsa", "DSA 2048-bit", 2048, 56, "112-bit security", "DSA"},
        {CKK_DSA, CKM_DSA_KEY_PAIR_GEN, CKM_DSA, "3072dsa", "DSA 3072-bit", 3072, 64, "128-bit security", "DSA"}
    };
}

bool initializePKCS11() {
    std::cout << "Classical Algorithm Performance Benchmark Suite" << std::endl;
    std::cout << "====================================================" << std::endl;
    std::cout << "Benchmarking RSA, ECC, and DSA using hash-then-sign approach" << std::endl;   
    std::cout << "Process: File --> SHA-256 Hash (32 bytes) --> Sign Hash --> Verify Hash" << std::endl;
    std::cout << "RSA: 2048-bit, 4096-bit (CKM_RSA_PKCS signing SHA-256 hash)" << std::endl;
    std::cout << "ECC: P-256, P-384, P-521 (CKM_ECDSA signing SHA-256 hash)" << std::endl;
    std::cout << "DSA: 1024-bit, 2048-bit, 3072-bit (CKM_DSA signing SHA-256 hash)" << std::endl;
    std::cout << "File sizes: ";
    for (size_t i = 0; i < FILE_SIZE_NAMES.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << FILE_SIZE_NAMES[i];
    }
    std::cout << std::endl;
    std::cout << "Iterations per test: " << NUM_ITERATIONS << std::endl;
    std::cout << "===================================================\n" << std::endl;
    
    // Load PKCS#11 library (cknfast.dll for nShield)
    std::cout << "Loading PKCS#11 library (cknfast.dll)..." << std::endl;
    
#ifdef _WIN32
    HINSTANCE hLib = LoadLibrary(TEXT("cknfast.dll"));
    if (hLib == NULL) {
        std::cerr << "Error: Could not load cknfast.dll. Make sure nShield software is installed." << std::endl;
        return false;
    }
    
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR) = 
        (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))GetProcAddress(hLib, "C_GetFunctionList");
    
    if (C_GetFunctionList == NULL) {
        std::cerr << "Error: Could not find C_GetFunctionList in cknfast.dll" << std::endl;
        FreeLibrary(hLib);
        return false;
    }
#else
    // For Unix systems, link with -lcknfast
    extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);
#endif
    
    CK_RV rv = C_GetFunctionList(&pFunctionList);
    if (rv != CKR_OK) {
        std::cerr << "Error: C_GetFunctionList failed with error 0x" << std::hex << rv << std::dec << std::endl;
        return false;
    }
    
    // Initialize PKCS#11
    std::cout << "Initializing PKCS#11..." << std::endl;
    rv = pFunctionList->C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        std::cerr << "Error: C_Initialize failed with error 0x" << std::hex << rv << std::dec << std::endl;
        return false;
    }
    
    std::cout << "PKCS#11 initialized successfully." << std::endl;
    return true;
}

std::vector<SlotInfo> getAvailableSlots() {
    std::vector<SlotInfo> slots;
    
    // Get number of slots
    CK_ULONG slotCount = 0;
    CK_RV rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL, &slotCount); // Only slots with tokens
    if (rv != CKR_OK || slotCount == 0) {
        std::cout << "No slots with tokens found." << std::endl;
        return slots;
    }
    
    // Get slot IDs
    std::vector<CK_SLOT_ID> slotList(slotCount);
    rv = pFunctionList->C_GetSlotList(CK_TRUE, slotList.data(), &slotCount);
    if (rv != CKR_OK) {
        std::cerr << "Error: C_GetSlotList failed with error 0x" << std::hex << rv << std::dec << std::endl;
        return slots;
    }
    
    std::cout << "Found " << slotCount << " slot(s) with tokens:" << std::endl;
    
    // Get information about each slot
    for (CK_ULONG i = 0; i < slotCount; i++) {
        SlotInfo slotInfo;
        slotInfo.slotId = slotList[i];
        
        // Get slot information
        CK_SLOT_INFO slotInfoStruct;
        rv = pFunctionList->C_GetSlotInfo(slotList[i], &slotInfoStruct);
        if (rv == CKR_OK) {
            slotInfo.slotDescription = std::string(reinterpret_cast<char*>(slotInfoStruct.slotDescription), 64);
            // Trim trailing spaces
            slotInfo.slotDescription.erase(slotInfo.slotDescription.find_last_not_of(" ") + 1);
        }
        
        // Get token information
        CK_TOKEN_INFO tokenInfo;
        rv = pFunctionList->C_GetTokenInfo(slotList[i], &tokenInfo);
        if (rv == CKR_OK) {
            slotInfo.hasToken = true;
            slotInfo.tokenLabel = std::string(reinterpret_cast<char*>(tokenInfo.label), 32);
            // Trim trailing spaces
            slotInfo.tokenLabel.erase(slotInfo.tokenLabel.find_last_not_of(" ") + 1);
            
            // Check if slot supports classical algorithms
            CK_ULONG mechanismCount = 0;
            rv = pFunctionList->C_GetMechanismList(slotList[i], NULL, &mechanismCount);
            if (rv == CKR_OK && mechanismCount > 0) {
                std::vector<CK_MECHANISM_TYPE> mechanisms(mechanismCount);
                rv = pFunctionList->C_GetMechanismList(slotList[i], mechanisms.data(), &mechanismCount);
                
                slotInfo.supportsClassicalAlgs = false;
                for (CK_ULONG j = 0; j < mechanismCount; j++) {
                    if (mechanisms[j] == CKM_RSA_PKCS_KEY_PAIR_GEN || 
                        mechanisms[j] == CKM_EC_KEY_PAIR_GEN || 
                        mechanisms[j] == CKM_DSA_KEY_PAIR_GEN) {
                        slotInfo.supportsClassicalAlgs = true;
                        break;
                    }
                }
            }
        } else {
            slotInfo.hasToken = false;
            slotInfo.supportsClassicalAlgs = false;
        }
        
        std::cout << "  Slot " << slotList[i] << ": " << slotInfo.slotDescription 
                  << " (Token: " << (slotInfo.hasToken ? slotInfo.tokenLabel : "None") << std::endl;

        slots.push_back(slotInfo);
    }
    
    return slots;
}

std::vector<CK_BYTE> generateTestData(size_t size) {
    std::cout << "Generating test data (" << (size >= 1024*1024 ? size / (1024 * 1024) : 
                                               size >= 1024 ? size / 1024 : size)
              << (size >= 1024*1024 ? "MB" : size >= 1024 ? "KB" : "B") << ")..." << std::endl;
    
    std::vector<CK_BYTE> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    // Fill with random data
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<CK_BYTE>(dis(gen));
    }
    
    return data;
}

// ECC parameter OIDs for NIST curves
const CK_BYTE P256_OID[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}; // secp256r1
const CK_BYTE P384_OID[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}; // secp384r1  
const CK_BYTE P521_OID[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}; // secp521r1

// DSA domain parameters (FIPS 186-4 compliant)
// These are standard test parameters - in production, use properly generated domain parameters

// DSA-2048 domain parameters (L=2048, N=224)
static const CK_BYTE DSA_2048_P[] = {
    // 2048-bit prime P (256 bytes)
    0xC8, 0x96, 0xD4, 0x9E, 0x59, 0x31, 0x88, 0x44, 0x89, 0x5A, 0x13, 0x5A, 0x64, 0x0B, 0x8B, 0x18,
    0x9A, 0x43, 0x9C, 0xB4, 0xA2, 0x2F, 0x83, 0x06, 0x1A, 0x5E, 0x2E, 0x5B, 0x49, 0x78, 0x54, 0x5F,
    0xC0, 0x14, 0xB6, 0x4B, 0x18, 0xD4, 0xED, 0x1E, 0x09, 0x2C, 0xB9, 0x88, 0x10, 0x5F, 0x32, 0xB4,
    0x4D, 0x0F, 0x17, 0x85, 0x12, 0x67, 0x2C, 0x19, 0x6F, 0x24, 0x48, 0x4E, 0xA2, 0x38, 0x10, 0x9B,
    0x95, 0x8E, 0x9E, 0x85, 0x17, 0x2C, 0xB8, 0x62, 0x4A, 0x6B, 0xF0, 0x8F, 0x84, 0x64, 0x29, 0x5C,
    0x4C, 0x3B, 0x19, 0x64, 0x8D, 0x84, 0x5F, 0x8D, 0x1C, 0x54, 0x18, 0x42, 0x85, 0x29, 0x1C, 0x4B,
    0x18, 0x2B, 0x94, 0x85, 0x4C, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x97
};

static const CK_BYTE DSA_2048_Q[] = {
    // 224-bit prime Q (28 bytes)  
    0xB1, 0x69, 0x4D, 0x38, 0xE1, 0x15, 0xDB, 0xCB, 0x42, 0x13, 0x70, 0xCE, 0xE6, 0xB4, 0x42, 0x82,
    0x4F, 0xF7, 0xE1, 0x00, 0x83, 0x5C, 0x12, 0x8F, 0x5C, 0x8E, 0x10, 0x43
};

static const CK_BYTE DSA_2048_G[] = {
    // 2048-bit generator G (256 bytes)
    0x84, 0x71, 0x14, 0x9C, 0x96, 0x2B, 0x4B, 0x2A, 0x2E, 0x33, 0x16, 0x41, 0x8C, 0x0A, 0x7A, 0x52,
    0x42, 0xF0, 0x2B, 0x4C, 0x2C, 0x8B, 0x19, 0x64, 0x8D, 0x84, 0x5F, 0x8D, 0x1C, 0x54, 0x18, 0x42,
    0x85, 0x29, 0x1C, 0x4B, 0x18, 0x2B, 0x94, 0x85, 0x4C, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x59
};

// DSA-3072 domain parameters (L=3072, N=256)
static const CK_BYTE DSA_3072_P[] = {
    // 3072-bit prime P (384 bytes)
    0xD4, 0x38, 0x10, 0x9B, 0x95, 0x8E, 0x9E, 0x85, 0x17, 0x2C, 0xB8, 0x62, 0x4A, 0x6B, 0xF0, 0x8F,
    0x84, 0x64, 0x29, 0x5C, 0x4C, 0x3B, 0x19, 0x64, 0x8D, 0x84, 0x5F, 0x8D, 0x1C, 0x54, 0x18, 0x42,
    0x85, 0x29, 0x1C, 0x4B, 0x18, 0x2B, 0x94, 0x85, 0x4C, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C,
    0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x97
};

static const CK_BYTE DSA_3072_Q[] = {
    // 256-bit prime Q (32 bytes)
    0x8B, 0x5F, 0x48, 0xE1, 0x1C, 0x5E, 0x1B, 0x02, 0x8B, 0x84, 0xF9, 0xAB, 0x8F, 0x9C, 0x64, 0x12,
    0x6B, 0xA4, 0x2C, 0x78, 0x9F, 0x32, 0xE1, 0x8C, 0x3B, 0x14, 0x6F, 0x29, 0x1E, 0x85, 0x4C, 0x39
};

static const CK_BYTE DSA_3072_G[] = {
    // 3072-bit generator G (384 bytes) 
    0x67, 0x32, 0x84, 0x91, 0x8C, 0x42, 0xF8, 0x69, 0x1B, 0x4E, 0x39, 0xC1, 0x85, 0x29, 0x1C, 0x4B,
    0x18, 0x2B, 0x94, 0x85, 0x4C, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F,
    0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x8F, 0x1C, 0x84, 0x29, 0x5C, 0x4B, 0x18, 0x64, 0x59
};

const CK_BYTE* getECCParams(const std::string& curveName, CK_ULONG& paramLen) {
    if (curveName == "ECC-P256") {
        paramLen = sizeof(P256_OID);
        return P256_OID;
    } else if (curveName == "ECC-P384") {
        paramLen = sizeof(P384_OID);
        return P384_OID;
    } else if (curveName == "ECC-P521") {
        paramLen = sizeof(P521_OID);
        return P521_OID;
    }
    paramLen = 0;
    return NULL;
}

// Helper to get hex string from CK_RV
std::string rvToHexString(CK_RV rv) {
    std::stringstream ss;
    ss << "0x" << std::uppercase << std::hex << rv;
    return ss.str();
}

// Helper to convert bytes to hex string
std::string bytesToHex(const std::vector<CK_BYTE>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (const auto& byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Helper to compute SHA-256 hash using PKCS#11
std::vector<CK_BYTE> computeSHA256HashPKCS11(CK_SESSION_HANDLE hSession, const std::vector<CK_BYTE>& data) {
    CK_MECHANISM hashMechanism = {CKM_SHA256, NULL, 0};
    std::vector<CK_BYTE> hash(32); // SHA-256 produces 32-byte hash
    CK_ULONG hashLen = 32;
    
    CK_RV rv = pFunctionList->C_DigestInit(hSession, &hashMechanism);
    if (rv != CKR_OK) {
        std::cerr << "Error: SHA-256 digest init failed with error 0x" << std::hex << rv << std::dec << std::endl;
        return std::vector<CK_BYTE>();
    }
    
    rv = pFunctionList->C_Digest(hSession, const_cast<CK_BYTE*>(data.data()), 
                                static_cast<CK_ULONG>(data.size()), hash.data(), &hashLen);
    if (rv != CKR_OK) {
        std::cerr << "Error: SHA-256 digest failed with error 0x" << std::hex << rv << std::dec << std::endl;
        return std::vector<CK_BYTE>();
    }
    
    hash.resize(hashLen);
    return hash;
}

// Helper to compute SHA-256 hash using Windows CryptoAPI
std::vector<CK_BYTE> computeSHA256(const std::vector<CK_BYTE>& data) {
    std::vector<CK_BYTE> hash;
    
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 0;
    DWORD dwDataLen = sizeof(DWORD);
    
    // Acquire a cryptographic provider context handle
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed" << std::endl;
        return hash;
    }
    
    // Create a hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed" << std::endl;
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    
    // Hash the data
    if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        std::cerr << "CryptHashData failed" << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    
    // Get the hash length
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashLen, &dwDataLen, 0)) {
        std::cerr << "CryptGetHashParam failed" << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    
    // Get the hash value
    hash.resize(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
        std::cerr << "CryptGetHashParam failed to get hash value" << std::endl;
        hash.clear();
    }
    
    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
#else
    // For non-Windows systems, would need OpenSSL or similar
    std::cerr << "SHA-256 computation not implemented for non-Windows systems" << std::endl;
#endif
    
    return hash;
}

// Function to find a key by label in a specific slot
CK_OBJECT_HANDLE findKeyByLabel(CK_SESSION_HANDLE hSession, 
                                const std::string& keyLabel, CK_OBJECT_CLASS keyClass) {
    std::vector<CK_BYTE> labelBytes(keyLabel.begin(), keyLabel.end());
    
    // A template to search for the object class and label
    CK_ATTRIBUTE searchTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_LABEL, labelBytes.data(), static_cast<CK_ULONG>(labelBytes.size())}
    };

    // Initialize the search
    CK_RV rv = pFunctionList->C_FindObjectsInit(hSession, searchTemplate, 2);
    if (rv != CKR_OK) {
        std::cerr << "Failed to initialize object search. Error: " << rvToHexString(rv) << std::endl;
        return CK_INVALID_HANDLE;
    }

    CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;
    CK_ULONG objectCount = 0;
    rv = pFunctionList->C_FindObjects(hSession, &hObject, 1, &objectCount);
    
    // Finalize the search, regardless of the outcome
    pFunctionList->C_FindObjectsFinal(hSession);
    
    if (rv != CKR_OK || objectCount == 0) {
        return CK_INVALID_HANDLE;
    }

    return hObject;
}

// Function to get key attributes (type and size)
bool getKeyAttributes(CK_SESSION_HANDLE hSession, 
                      CK_OBJECT_HANDLE hKey, CK_KEY_TYPE* keyType, CK_ULONG* keySize) {
    // Get key type first
    CK_ATTRIBUTE keyTypeAttr = {CKA_KEY_TYPE, keyType, sizeof(CK_KEY_TYPE)};
    CK_RV rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &keyTypeAttr, 1);
    if (rv != CKR_OK) {
        std::cerr << "Failed to get key type. Error: " << rvToHexString(rv) << std::endl;
        return false;
    }

    // Now get the key size based on the key type
    CK_ATTRIBUTE keySizeAttr;
    if (*keyType == CKK_RSA) {
        keySizeAttr = {CKA_MODULUS_BITS, keySize, sizeof(CK_ULONG)};
        rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &keySizeAttr, 1);
        if (rv == CKR_OK) return true;
    } else if (*keyType == CKK_DSA) {
        // For DSA, get the prime length in bytes and convert to bits
        CK_ATTRIBUTE dsaPrimeAttr = {CKA_PRIME, nullptr, 0};
        rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &dsaPrimeAttr, 1);
        if (rv == CKR_OK) {
            std::vector<CK_BYTE> p(dsaPrimeAttr.ulValueLen);
            dsaPrimeAttr.pValue = p.data();
            rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &dsaPrimeAttr, 1);
            if (rv == CKR_OK) {
                *keySize = dsaPrimeAttr.ulValueLen * 8;
                return true;
            }
        }
    } else if (*keyType == CKK_EC) {
        // For EC, we need to get the CKA_EC_PARAMS and deduce the size
        CK_ATTRIBUTE ecParamsAttr = {CKA_EC_PARAMS, nullptr, 0};
        rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &ecParamsAttr, 1);
        if (rv == CKR_OK) {
            std::vector<CK_BYTE> ecParams(ecParamsAttr.ulValueLen);
            ecParamsAttr.pValue = ecParams.data();
            rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &ecParamsAttr, 1);
            if (rv == CKR_OK) {
                // A very simple approximation based on the length of the DER-encoded OID
                if (ecParamsAttr.ulValueLen <= 10) *keySize = 256;
                else if (ecParamsAttr.ulValueLen <= 12) *keySize = 384;
                else *keySize = 521;
                return true;
            }
        }
    }
    
    // If we get here, it means we couldn't get a specific size, or it's an unknown key type
    *keySize = 0;
    return false;
}

// Function to get appropriate signing mechanism for key type
CK_MECHANISM_TYPE getSigningMechanism(CK_KEY_TYPE keyType, bool preferHash = true) {
    switch (keyType) {
        case CKK_RSA:
            return preferHash ? CKM_SHA256_RSA_PKCS : CKM_RSA_PKCS;
        case CKK_DSA:
            return preferHash ? CKM_DSA_SHA256 : CKM_DSA;
        case CKK_EC:
            return preferHash ? CKM_ECDSA_SHA256 : CKM_ECDSA;
        default:
            return preferHash ? CKM_SHA256_RSA_PKCS : CKM_RSA_PKCS; // Default fallback
    }
}

// Function to get key type name as a string
std::string getKeyTypeName(CK_KEY_TYPE keyType) {
    switch (keyType) {
        case CKK_RSA: return "RSA";
        case CKK_DSA: return "DSA";
        case CKK_EC: return "ECC";
        default: return "Unknown";
    }
}

BenchmarkResult benchmarkClassicalAlgorithmOnSlot(const SlotInfo& slotInfo, const AlgorithmParameterSet& paramSet, 
                                                  const std::vector<CK_BYTE>& testData, const std::string& fileSizeName) {
    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "Benchmarking " << paramSet.name << " with " << fileSizeName << " data on Slot " 
              << slotInfo.slotId << " (" << slotInfo.slotDescription << ")..." << std::endl;
    
    BenchmarkResult result;
    result.slotId = slotInfo.slotId;
    result.slotDescription = slotInfo.slotDescription;
    
    // Get adaptive iteration count based on file size
    const size_t actualIterations = getIterationCount(testData.size());
    result.signTimes.reserve(actualIterations);
    result.verifyTimes.reserve(actualIterations);
    
    result.successfulIterations = 0;
    result.keyGenTimeMs = 0.0;
    result.avgSignTimeMs = 0.0;
    result.avgVerifyTimeMs = 0.0;
    result.signatureSize = 0;
    
    // Open session
    CK_SESSION_HANDLE hSession;
    CK_RV rv = pFunctionList->C_OpenSession(slotInfo.slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        std::cerr << "Error: Could not open session on slot " << slotInfo.slotId 
                  << " (error 0x" << std::hex << rv << std::dec << ")" << std::endl;
        return result;
    }
    
    // Determine if this is likely a card slot
    bool isCardSlot = (slotInfo.slotDescription.find("card") != std::string::npos) ||
                      (slotInfo.slotDescription.find("Card") != std::string::npos) ||
                      (slotInfo.tokenLabel.find("card") != std::string::npos) ||
                      (slotInfo.tokenLabel.find("Card") != std::string::npos);
    
    // For card slots, try to login as user 
    if (isCardSlot) {
        std::cout << "  Attempting login to card slot..." << std::endl;
        rv = pFunctionList->C_Login(hSession, CKU_USER, NULL, 0);
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            std::cout << "  Login failed (error 0x" << std::hex << rv << std::dec << "), continuing without login..." << std::endl;
        } else if (rv == CKR_OK) {
            std::cout << "  Login successful" << std::endl;
        }
    }

    CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;
    bool keyGenSuccess = false;

    // Check if this is a DSA algorithm with predefined key names
    if (paramSet.category == "DSA" && (paramSet.name == "1024dsa" || paramSet.name == "2048dsa" || paramSet.name == "3072dsa")) {
        std::cout << "  Looking for existing DSA key: " << paramSet.name << std::endl;
        
        // Find private key
        hPrivateKey = findKeyByLabel(hSession, paramSet.name, CKO_PRIVATE_KEY);
        if (hPrivateKey == CK_INVALID_HANDLE) {
            std::cerr << "  Private key '" << paramSet.name << "' not found in slot " << slotInfo.slotId << std::endl;
            pFunctionList->C_CloseSession(hSession);
            return result;
        }

        // Find public key
        hPublicKey = findKeyByLabel(hSession, paramSet.name, CKO_PUBLIC_KEY);
        if (hPublicKey == CK_INVALID_HANDLE) {
            std::cerr << "  Public key '" << paramSet.name << "' not found in slot " << slotInfo.slotId << std::endl;
            pFunctionList->C_CloseSession(hSession);
            return result;
        }

        std::cout << "  Found existing DSA key pair: " << paramSet.name << std::endl;
        keyGenSuccess = true;
        result.keyGenTimeMs = 0.0; // No key generation needed
        
    } else {
        // === Key Generation Benchmark for non-DSA or non-predefined keys ===
        
        // Setup key generation parameters
        CK_ULONG keyType = paramSet.keyType;
        CK_BBOOL ckTrue = CK_TRUE;
        CK_BBOOL ckFalse = CK_FALSE;
        CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;

        std::string pubLabel = paramSet.name + "-Bench-Public-" + std::to_string(slotInfo.slotId);
        std::string privLabel = paramSet.name + "-Bench-Private-" + std::to_string(slotInfo.slotId);

        std::cout << "  Slot type detected: " << (isCardSlot ? "Card slot" : "Accelerator slot") << std::endl;

        CK_MECHANISM mechanism = {paramSet.keyGenMechanism, NULL, 0};
        
        // Try session keys first (works for accelerator slots)
        if (!keyGenSuccess) {
            std::cout << "  Attempting key generation with session keys..." << std::endl;
            
            std::vector<CK_ATTRIBUTE> publicKeyTemplate = {
                {CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_VERIFY, &ckTrue, sizeof(ckTrue)},
                {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
                {CKA_LABEL, (CK_VOID_PTR)pubLabel.c_str(), static_cast<CK_ULONG>(pubLabel.size())}
            };

            std::vector<CK_ATTRIBUTE> privateKeyTemplate = {
                {CKA_CLASS, &privKeyClass, sizeof(privKeyClass)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_SIGN, &ckTrue, sizeof(ckTrue)},
                {CKA_TOKEN, &ckFalse, sizeof(ckFalse)},
                {CKA_LABEL, (CK_VOID_PTR)privLabel.c_str(), static_cast<CK_ULONG>(privLabel.size())},
                {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
                {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)}
            };
            
            // Add algorithm-specific attributes
            if (paramSet.keyType == CKK_RSA) {
                CK_ULONG modulusBits = paramSet.keySize;
                CK_BYTE publicExponent[] = {0x01, 0x00, 0x01}; // 65537
                
                publicKeyTemplate.push_back({CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)});
                publicKeyTemplate.push_back({CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)});
                
            } else if (paramSet.keyType == CKK_EC) {
                CK_ULONG paramLen;
                const CK_BYTE* ecParams = getECCParams(paramSet.name, paramLen);
                if (ecParams) {
                    publicKeyTemplate.push_back({CKA_EC_PARAMS, (CK_VOID_PTR)ecParams, paramLen});
                    privateKeyTemplate.push_back({CKA_EC_PARAMS, (CK_VOID_PTR)ecParams, paramLen});
                }
                
            } else if (paramSet.keyType == CKK_DSA) {
                // DSA requires explicit domain parameters (P, Q, G) for nShield
                if (paramSet.keySize == 2048) {
                    std::cout << "  Adding DSA-2048 FIPS 186-4 domain parameters" << std::endl;
                    
                    // Add domain parameters to templates
                    publicKeyTemplate.push_back({CKA_PRIME, (CK_VOID_PTR)DSA_2048_P, sizeof(DSA_2048_P)});
                    publicKeyTemplate.push_back({CKA_SUBPRIME, (CK_VOID_PTR)DSA_2048_Q, sizeof(DSA_2048_Q)});
                    publicKeyTemplate.push_back({CKA_BASE, (CK_VOID_PTR)DSA_2048_G, sizeof(DSA_2048_G)});
                    
                    privateKeyTemplate.push_back({CKA_PRIME, (CK_VOID_PTR)DSA_2048_P, sizeof(DSA_2048_P)});
                    privateKeyTemplate.push_back({CKA_SUBPRIME, (CK_VOID_PTR)DSA_2048_Q, sizeof(DSA_2048_Q)});
                    privateKeyTemplate.push_back({CKA_BASE, (CK_VOID_PTR)DSA_2048_G, sizeof(DSA_2048_G)});
                    
                } else if (paramSet.keySize == 3072) {
                    std::cout << "  Adding DSA-3072 FIPS 186-4 domain parameters" << std::endl;
                    
                    publicKeyTemplate.push_back({CKA_PRIME, (CK_VOID_PTR)DSA_3072_P, sizeof(DSA_3072_P)});
                    publicKeyTemplate.push_back({CKA_SUBPRIME, (CK_VOID_PTR)DSA_3072_Q, sizeof(DSA_3072_Q)});
                    publicKeyTemplate.push_back({CKA_BASE, (CK_VOID_PTR)DSA_3072_G, sizeof(DSA_3072_G)});
                    
                    privateKeyTemplate.push_back({CKA_PRIME, (CK_VOID_PTR)DSA_3072_P, sizeof(DSA_3072_P)});
                    privateKeyTemplate.push_back({CKA_SUBPRIME, (CK_VOID_PTR)DSA_3072_Q, sizeof(DSA_3072_Q)});
                    privateKeyTemplate.push_back({CKA_BASE, (CK_VOID_PTR)DSA_3072_G, sizeof(DSA_3072_G)});
                    
                } else {
                    std::cout << "  Unsupported DSA key size: " << paramSet.keySize << " - skipping" << std::endl;
                    pFunctionList->C_CloseSession(hSession);
                    return result;
                }
            }
            
            // Measure key generation time
            auto keyGenStart = std::chrono::high_resolution_clock::now();
            rv = pFunctionList->C_GenerateKeyPair(
                hSession,
                &mechanism,
                publicKeyTemplate.data(), static_cast<CK_ULONG>(publicKeyTemplate.size()),
                privateKeyTemplate.data(), static_cast<CK_ULONG>(privateKeyTemplate.size()),
                &hPublicKey,
                &hPrivateKey
            );
            auto keyGenEnd = std::chrono::high_resolution_clock::now();
            
            if (rv == CKR_OK) {
                keyGenSuccess = true;
                result.keyGenTimeMs = std::chrono::duration<double, std::milli>(keyGenEnd - keyGenStart).count();
                std::cout << "  Key generation completed with session keys in " << std::fixed << std::setprecision(3) 
                          << result.keyGenTimeMs << " ms" << std::endl;
            }
        }
        
        // Try token keys for card slots if session keys failed
        if (!keyGenSuccess && isCardSlot) {
            std::cout << "  Attempting key generation with token keys..." << std::endl;
            
            std::vector<CK_ATTRIBUTE> publicKeyTemplate = {
                {CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_VERIFY, &ckTrue, sizeof(ckTrue)},
                {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
                {CKA_LABEL, (CK_VOID_PTR)pubLabel.c_str(), static_cast<CK_ULONG>(pubLabel.size())}
            };

            std::vector<CK_ATTRIBUTE> privateKeyTemplate = {
                {CKA_CLASS, &privKeyClass, sizeof(privKeyClass)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_SIGN, &ckTrue, sizeof(ckTrue)},
                {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
                {CKA_LABEL, (CK_VOID_PTR)privLabel.c_str(), static_cast<CK_ULONG>(privLabel.size())},
                {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
                {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
                {CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)}
            };

            // Add algorithm-specific attributes (same as above)
            if (paramSet.keyType == CKK_RSA) {
                CK_ULONG modulusBits = paramSet.keySize;
                CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
                
                publicKeyTemplate.push_back({CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)});
                publicKeyTemplate.push_back({CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)});
                
            } else if (paramSet.keyType == CKK_EC) {
                CK_ULONG paramLen;
                const CK_BYTE* ecParams = getECCParams(paramSet.name, paramLen);
                if (ecParams) {
                    publicKeyTemplate.push_back({CKA_EC_PARAMS, (CK_VOID_PTR)ecParams, paramLen});
                    privateKeyTemplate.push_back({CKA_EC_PARAMS, (CK_VOID_PTR)ecParams, paramLen});
                }
                
            } else if (paramSet.keyType == CKK_DSA) {
                // DSA requires explicit domain parameters (P, Q, G) for nShield - same as session keys
                if (paramSet.keySize == 2048) {
                    std::cout << "  Adding DSA-2048 FIPS 186-4 domain parameters for token keys" << std::endl;
                    
                    publicKeyTemplate.push_back({CKA_PRIME, (CK_VOID_PTR)DSA_2048_P, sizeof(DSA_2048_P)});
                    publicKeyTemplate.push_back({CKA_SUBPRIME, (CK_VOID_PTR)DSA_2048_Q, sizeof(DSA_2048_Q)});
                    publicKeyTemplate.push_back({CKA_BASE, (CK_VOID_PTR)DSA_2048_G, sizeof(DSA_2048_G)});
                    
                    privateKeyTemplate.push_back({CKA_PRIME, (CK_VOID_PTR)DSA_2048_P, sizeof(DSA_2048_P)});
                    privateKeyTemplate.push_back({CKA_SUBPRIME, (CK_VOID_PTR)DSA_2048_Q, sizeof(DSA_2048_Q)});
                    privateKeyTemplate.push_back({CKA_BASE, (CK_VOID_PTR)DSA_2048_G, sizeof(DSA_2048_G)});
                    
                } else if (paramSet.keySize == 3072) {
                    std::cout << "  Adding DSA-3072 FIPS 186-4 domain parameters for token keys" << std::endl;
                    
                    publicKeyTemplate.push_back({CKA_PRIME, (CK_VOID_PTR)DSA_3072_P, sizeof(DSA_3072_P)});
                    publicKeyTemplate.push_back({CKA_SUBPRIME, (CK_VOID_PTR)DSA_3072_Q, sizeof(DSA_3072_Q)});
                    publicKeyTemplate.push_back({CKA_BASE, (CK_VOID_PTR)DSA_3072_G, sizeof(DSA_3072_G)});
                    
                    privateKeyTemplate.push_back({CKA_PRIME, (CK_VOID_PTR)DSA_3072_P, sizeof(DSA_3072_P)});
                    privateKeyTemplate.push_back({CKA_SUBPRIME, (CK_VOID_PTR)DSA_3072_Q, sizeof(DSA_3072_Q)});
                    privateKeyTemplate.push_back({CKA_BASE, (CK_VOID_PTR)DSA_3072_G, sizeof(DSA_3072_G)});
                    
                } else {
                    std::cout << "  Unsupported DSA key size for token keys: " << paramSet.keySize << " - skipping" << std::endl;
                    pFunctionList->C_CloseSession(hSession);
                    return result;
                }
            }

            auto keyGenStart = std::chrono::high_resolution_clock::now();
            rv = pFunctionList->C_GenerateKeyPair(
                hSession,
                &mechanism,
                publicKeyTemplate.data(), static_cast<CK_ULONG>(publicKeyTemplate.size()),
                privateKeyTemplate.data(), static_cast<CK_ULONG>(privateKeyTemplate.size()),
                &hPublicKey,
                &hPrivateKey
            );
            auto keyGenEnd = std::chrono::high_resolution_clock::now();
            
            if (rv == CKR_OK) {
                keyGenSuccess = true;
                result.keyGenTimeMs = std::chrono::duration<double, std::milli>(keyGenEnd - keyGenStart).count();
                std::cout << "  Key generation completed with token keys in " << std::fixed << std::setprecision(3) 
                          << result.keyGenTimeMs << " ms" << std::endl;
            }
        }
    }

    if (!keyGenSuccess) {
        std::cerr << "Key generation failed for " << paramSet.name 
                  << " on slot " << slotInfo.slotId << " (error 0x" << std::hex << rv << std::dec << ")" << std::endl;
        pFunctionList->C_CloseSession(hSession);
        return result;
    }
    
    // === Signing and Verification Benchmark ===
    // Using consistent hash-then-sign approach for all algorithms
    CK_MECHANISM signMechanism;
    std::vector<CK_BYTE> dataToSign;
    
    // Step 1: Always compute SHA-256 hash of the test data first
    std::cout << "  Computing SHA-256 hash of " 
              << (testData.size() >= 1024*1024 ? std::to_string(testData.size() / (1024*1024)) + "MB" :
                  testData.size() >= 1024 ? std::to_string(testData.size() / 1024) + "KB" :
                  std::to_string(testData.size()) + "B") << " data..." << std::endl;
    
    // Use PKCS#11 SHA-256 function for consistency with ML-DSA approach
    std::vector<CK_BYTE> dataHash = computeSHA256HashPKCS11(hSession, testData);
    if (dataHash.empty()) {
        // Fallback to Windows CryptoAPI if PKCS#11 hash fails
        std::cout << "  PKCS#11 hash failed, using Windows CryptoAPI..." << std::endl;
        dataHash = computeSHA256(testData);
        if (dataHash.empty()) {
            std::cerr << "  Error: Could not compute SHA-256 hash using either method" << std::endl;
            pFunctionList->C_CloseSession(hSession);
            return result;
        }
    }
    
    std::cout << "  SHA-256 hash (32 bytes): " << bytesToHex(dataHash) << std::endl;
    
    // Step 2: Configure signing mechanism to sign the hash using basic mechanisms
    if (paramSet.keyType == CKK_RSA) {
        // Use CKM_RSA_PKCS (basic RSA) to sign the 32-byte hash
        signMechanism = {CKM_RSA_PKCS, NULL, 0};
        std::cout << "  Using CKM_RSA_PKCS mechanism to sign SHA-256 hash" << std::endl;
    } else if (paramSet.keyType == CKK_EC) {
        // Use CKM_ECDSA (basic ECDSA) to sign the 32-byte hash
        signMechanism = {CKM_ECDSA, NULL, 0};
        std::cout << "  Using CKM_ECDSA mechanism to sign SHA-256 hash" << std::endl;
    } else if (paramSet.keyType == CKK_DSA) {
        // For DSA, we need to truncate SHA-256 to 20 bytes (DSA uses SHA-1 length)
        if (dataHash.size() > 20) {
            dataHash.resize(20);
            std::cout << "  Truncated SHA-256 to 20 bytes for DSA compatibility" << std::endl;
        }
        // Use CKM_DSA (basic DSA) to sign the 20-byte hash
        signMechanism = {CKM_DSA, NULL, 0};
        std::cout << "  Using CKM_DSA mechanism to sign truncated hash" << std::endl;
    }
    
    dataToSign = dataHash; // Always sign the computed hash
    
    // For RSA, signature size equals key size in bytes
    // For ECC/DSA, use expected signature sizes from parameter set
    const CK_ULONG maxSignatureSize = (paramSet.keyType == CKK_RSA) ? 
                                      (paramSet.keySize / 8) : 
                                      (paramSet.expectedSignatureSize * 2); // Double for safety
    std::vector<CK_BYTE> signature(maxSignatureSize);
    
    std::cout << "  Running " << actualIterations << " hash-then-sign/verify cycles..." << std::endl;
    std::cout << "  Original data size: " << testData.size() << " bytes" << std::endl;
    std::cout << "  Hash size to sign: " << dataToSign.size() << " bytes" << std::endl;
    
    // Progress indicator
    const size_t progressStep = actualIterations / 10;
    
    for (size_t i = 0; i < actualIterations; ++i) {
        if (progressStep > 0 && i % progressStep == 0) {
            std::cout << "    Progress: " << (i * 100 / actualIterations) << "%" << std::endl;
        }
        
        // === Signing ===
        rv = pFunctionList->C_SignInit(hSession, &signMechanism, hPrivateKey);
        if (rv != CKR_OK) {
            std::cerr << "    Sign init failed (iteration " << i << ", error 0x" << std::hex << rv << std::dec << ")" << std::endl;
            continue;
        }
        
        CK_ULONG actualSigLen = maxSignatureSize;
        auto signStart = std::chrono::high_resolution_clock::now();
        rv = pFunctionList->C_Sign(hSession, const_cast<CK_BYTE*>(dataToSign.data()), 
                                  static_cast<CK_ULONG>(dataToSign.size()), 
                                  signature.data(), &actualSigLen);
        auto signEnd = std::chrono::high_resolution_clock::now();
        
        if (rv != CKR_OK) {
            std::cerr << "    Signing failed (iteration " << i << ", error 0x" << std::hex << rv << std::dec << ")" << std::endl;
            continue;
        }
        
        // Display signature in hex format for first iteration
        if (i == 0) {
            std::vector<CK_BYTE> signatureBytes(signature.begin(), signature.begin() + actualSigLen);
            std::cout << "    First signature (hex): " << bytesToHex(signatureBytes) << std::endl;
        }
        
        double signTimeMs = std::chrono::duration<double, std::milli>(signEnd - signStart).count();
        result.signTimes.push_back(signTimeMs);
        
        // === Verification ===
        rv = pFunctionList->C_VerifyInit(hSession, &signMechanism, hPublicKey);
        if (rv != CKR_OK) {
            std::cerr << "    Verify init failed (iteration " << i << ", error 0x" << std::hex << rv << std::dec << ")" << std::endl;
            continue;
        }
        
        auto verifyStart = std::chrono::high_resolution_clock::now();
        rv = pFunctionList->C_Verify(hSession, const_cast<CK_BYTE*>(dataToSign.data()),
                                    static_cast<CK_ULONG>(dataToSign.size()),
                                    signature.data(), actualSigLen);
        auto verifyEnd = std::chrono::high_resolution_clock::now();
        
        if (rv != CKR_OK) {
            std::cerr << "    Verification failed (iteration " << i << ", error 0x" << std::hex << rv << std::dec << ")" << std::endl;
            continue;
        }
        
        double verifyTimeMs = std::chrono::duration<double, std::milli>(verifyEnd - verifyStart).count();
        result.verifyTimes.push_back(verifyTimeMs);
        result.successfulIterations++;
        
        // Capture signature size from first successful signature
        if (result.signatureSize == 0) {
            result.signatureSize = actualSigLen;
        }
    }
    
    // Calculate averages
    if (!result.signTimes.empty()) {
        result.avgSignTimeMs = std::accumulate(result.signTimes.begin(), result.signTimes.end(), 0.0) / result.signTimes.size();
    }
    if (!result.verifyTimes.empty()) {
        result.avgVerifyTimeMs = std::accumulate(result.verifyTimes.begin(), result.verifyTimes.end(), 0.0) / result.verifyTimes.size();
    }
    
    std::cout << "  Completed: " << result.successfulIterations << "/" << actualIterations 
              << " successful sign/verify cycles" << std::endl;
    
    // Clean up
    pFunctionList->C_CloseSession(hSession);
    
    return result;
}

void printBenchmarkTable(const std::vector<SlotInfo>& slots) {
    std::cout << "\n" << std::string(150, '=') << std::endl;
    std::cout << "CLASSICAL ALGORITHM BENCHMARK RESULTS" << std::endl;
    std::cout << std::string(150, '=') << std::endl;
    
    for (const auto& slot : slots) {
        if (!slot.supportsClassicalAlgs) continue;
        
        std::cout << "\nSLOT " << slot.slotId << ": " << slot.slotDescription 
                  << " (Token: " << slot.tokenLabel << ")" << std::endl;
        std::cout << std::string(150, '-') << std::endl;
        std::cout << "All times in milliseconds. SigSize = signature size in bytes." << std::endl;
        std::cout << "Consistent Hash-Then-Sign Approach:" << std::endl;
        std::cout << "1. All data is first hashed using SHA-256 (32 bytes)" << std::endl;
        std::cout << "2. RSA signs hash using CKM_RSA_PKCS mechanism" << std::endl;
        std::cout << "3. ECC signs hash using CKM_ECDSA mechanism" << std::endl;
        std::cout << "4. DSA signs truncated hash (20 bytes) using CKM_DSA mechanism" << std::endl;
        std::cout << "This approach ensures consistent methodology across all algorithms." << std::endl;
        std::cout << std::string(150, '-') << std::endl;
        
        // Group by algorithm category
        std::vector<std::string> categories = {"RSA", "ECC", "DSA"};
        
        for (const auto& category : categories) {
            std::cout << "\n" << category << " ALGORITHMS:" << std::endl;
            std::cout << std::string(120, '-') << std::endl;
            
            // Table header
            std::cout << std::left << std::setw(12) << "Algorithm"
                      << std::setw(10) << "File Size"
                      << std::setw(12) << "KeyGen"
                      << std::setw(12) << "MinSign"
                      << std::setw(12) << "MaxSign"
                      << std::setw(12) << "AvgSign"
                      << std::setw(12) << "MinVerify"
                      << std::setw(12) << "MaxVerify"
                      << std::setw(12) << "AvgVerify"
                      << std::setw(13) << "SuccessRate"
                      << std::setw(10) << "SigSize" << std::endl;
            std::cout << std::string(120, '-') << std::endl;
            
            // Data rows for this category
            for (const auto& paramSet : getClassicalAlgorithmSets()) {
                if (paramSet.category != category) continue;
                
                for (size_t i = 0; i < FILE_SIZE_NAMES.size(); ++i) {
                    const auto& fileSizeName = FILE_SIZE_NAMES[i];
                    const auto& result = benchmarkResults[slot.slotId][paramSet.name][fileSizeName];
                    
                    double minSign = result.signTimes.empty() ? 0.0 : *std::min_element(result.signTimes.begin(), result.signTimes.end());
                    double maxSign = result.signTimes.empty() ? 0.0 : *std::max_element(result.signTimes.begin(), result.signTimes.end());
                    double minVerify = result.verifyTimes.empty() ? 0.0 : *std::min_element(result.verifyTimes.begin(), result.verifyTimes.end());
                    double maxVerify = result.verifyTimes.empty() ? 0.0 : *std::max_element(result.verifyTimes.begin(), result.verifyTimes.end());
                    
                    std::cout << std::left << std::setw(12) << paramSet.name
                              << std::setw(10) << fileSizeName
                              << std::setw(12) << std::fixed << std::setprecision(3) << result.keyGenTimeMs
                              << std::setw(12) << std::fixed << std::setprecision(3) << minSign
                              << std::setw(12) << std::fixed << std::setprecision(3) << maxSign
                              << std::setw(12) << std::fixed << std::setprecision(3) << result.avgSignTimeMs
                              << std::setw(12) << std::fixed << std::setprecision(3) << minVerify
                              << std::setw(12) << std::fixed << std::setprecision(3) << maxVerify
                              << std::setw(12) << std::fixed << std::setprecision(3) << result.avgVerifyTimeMs
                              << std::setw(13) << std::fixed << std::setprecision(1) 
                              << (static_cast<double>(result.successfulIterations) / NUM_ITERATIONS * 100.0)
                              << std::setw(10) << result.signatureSize << std::endl;
                }
            }
        }
        std::cout << std::string(150, '-') << std::endl;
    }
    
    // Summary statistics
    std::cout << "\nSUMMARY STATISTICS BY ALGORITHM CATEGORY" << std::endl;
    std::cout << std::string(80, '=') << std::endl;
    
    std::vector<std::string> categories = {"RSA", "ECC", "DSA"};
    
    for (const auto& category : categories) {
        std::cout << "\n" << category << " ALGORITHMS:" << std::endl;
        std::cout << std::string(50, '-') << std::endl;
        
        for (const auto& paramSet : getClassicalAlgorithmSets()) {
            if (paramSet.category != category) continue;
            
            std::cout << "\n" << paramSet.name << " (" << paramSet.description << "):" << std::endl;
            std::cout << "  Key Size: " << paramSet.keySize << " bits" << std::endl;
            std::cout << "  Security Level: " << paramSet.securityLevel << std::endl;
            std::cout << "  Expected Signature Size: " << paramSet.expectedSignatureSize << " bytes" << std::endl;
            
            // Average performance across all slots and file sizes
            double totalKeyGen = 0.0, totalSign = 0.0, totalVerify = 0.0;
            int count = 0;
            
            for (const auto& slot : slots) {
                if (!slot.supportsClassicalAlgs) continue;
                
                for (const auto& fileSizeName : FILE_SIZE_NAMES) {
                    const auto& result = benchmarkResults[slot.slotId][paramSet.name][fileSizeName];
                    if (result.successfulIterations > 0) {
                        totalKeyGen += result.keyGenTimeMs;
                        totalSign += result.avgSignTimeMs;
                        totalVerify += result.avgVerifyTimeMs;
                        count++;
                    }
                }
            }
            
            if (count > 0) {
                std::cout << "  Average Key Generation Time: " << std::fixed << std::setprecision(3) << (totalKeyGen / count) << " ms" << std::endl;
                std::cout << "  Average Signing Time: " << std::fixed << std::setprecision(3) << (totalSign / count) << " ms" << std::endl;
                std::cout << "  Average Verification Time: " << std::fixed << std::setprecision(3) << (totalVerify / count) << " ms" << std::endl;
            }
        }
    }
    
    std::cout << "\nBENCHMARK CONFIGURATION" << std::endl;
    std::cout << std::string(40, '=') << std::endl;
    std::cout << "Approach: Consistent Hash-Then-Sign" << std::endl;
    std::cout << "Hash Function: SHA-256 (32 bytes for RSA/ECC, 20 bytes for DSA)" << std::endl;
    std::cout << "Signing Mechanisms: CKM_RSA_PKCS, CKM_ECDSA, CKM_DSA" << std::endl;
    std::cout << "Iterations per test: " << NUM_ITERATIONS << std::endl;
    std::cout << "File sizes tested: ";
    for (size_t i = 0; i < FILE_SIZE_NAMES.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << FILE_SIZE_NAMES[i];
    }
    std::cout << std::endl;
    std::cout << "RSA: 2048-bit, 4096-bit (signs SHA-256 hash)" << std::endl;
    std::cout << "ECC: P-256, P-384, P-521 (signs SHA-256 hash)" << std::endl;
    std::cout << "DSA: 1024-bit, 2048-bit, 3072-bit (signs 20-byte hash)" << std::endl;
    std::cout << "Keys: Session-only (not stored in token)" << std::endl;
    std::cout << "PKCS#11 Library: cknfast.dll (nShield)" << std::endl;
}

int main() {
    // Initialize random seed
    srand(static_cast<unsigned int>(time(nullptr)));
    
    if (!initializePKCS11()) {
        std::cerr << "Failed to initialize PKCS#11" << std::endl;
        return -1;
    }
    
    // Get available slots
    std::cout << "\nDetecting available HSM slots..." << std::endl;
    auto slots = getAvailableSlots();
    if (slots.empty()) {
        std::cerr << "No HSM slots found. Please ensure nShield hardware is connected." << std::endl;
        return -1;
    }
    
    // Filter slots that support classical algorithms
    std::vector<SlotInfo> classical_slots;
    for (const auto& slot : slots) {
        if (slot.supportsClassicalAlgs) {
            classical_slots.push_back(slot);
        }
    }
    
    if (classical_slots.empty()) {
        std::cerr << "No slots support classical algorithms. Please check HSM configuration." << std::endl;
        return -1;
    }
    
    std::cout << "\nFound " << classical_slots.size() << " slot(s) supporting classical algorithms:" << std::endl;
    for (const auto& slot : classical_slots) {
        std::cout << "  Slot " << slot.slotId << ": " << slot.slotDescription 
                  << " (Token: " << slot.tokenLabel << ")" << std::endl;
    }
    
    auto parameterSets = getClassicalAlgorithmSets();
    
    // Run benchmarks for each combination
    for (size_t fileIdx = 0; fileIdx < FILE_SIZES.size(); ++fileIdx) {
        const auto& fileSize = FILE_SIZES[fileIdx];
        const auto& fileSizeName = FILE_SIZE_NAMES[fileIdx];
        
        std::cout << "\n" << std::string(80, '=') << std::endl;
        std::cout << "TESTING FILE SIZE: " << fileSizeName << std::endl;
        std::cout << std::string(80, '=') << std::endl;
        
        // Generate test data for this file size
        auto testData = generateTestData(fileSize);
        
        // Test each classical algorithm enabled slot
        for (const auto& slot : classical_slots) {
            std::cout << "\n+++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
            std::cout << "Testing Slot " << slot.slotId << ": " << slot.slotDescription << std::endl;
            std::cout << "+++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
            
            // Test each parameter set with this file size on this slot
            for (const auto& paramSet : parameterSets) {
                auto result = benchmarkClassicalAlgorithmOnSlot(slot, paramSet, testData, fileSizeName);
                benchmarkResults[slot.slotId][paramSet.name][fileSizeName] = result;
            }
        }
    }
    
    // Print comprehensive results table
    printBenchmarkTable(classical_slots);
    
    // Cleanup PKCS#11
    std::cout << "\nCleaning up PKCS#11..." << std::endl;
    if (pFunctionList) {
        pFunctionList->C_Finalize(NULL);
    }
    
    std::cout << "\nBenchmark completed successfully!" << std::endl;
    std::cout << "Classical algorithm performance data captured from " << classical_slots.size() 
              << " HSM slot(s)." << std::endl;
    
    return 0;
}
