/*
 * ML-DSA Performance Benchmark using PKCS#11 with nShield HSM
 * 
 * This application benchmarks ML-DSA (Module-Lattice Digital Signature Algorithm) 
 * performance across different file sizes and parameter sets using actual PKCS#11
 * calls to nShield HSM slots:
 * - File sizes: 1KB, 10KB, 100KB, 200KB, 300KB
 * - Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87
 * - Tests all available HSM slots
 * - Metrics: Key generation, signing, verification times and signature sizes
 * - 100 iterations per test for statistical accuracy
 * 
 * IMPORTANT: nCipher nShield Usage Requirements & Empirical Findings
 * =================================================================
 * 
 * 1. ML-DSA Message Size Handling - CONFIRMED HARD LIMIT:
 *    Empirical testing proves the HARD LIMIT for one-shot ML-DSA signing is 200KB.
 *    - 1KB-200KB: 100% success rate (all parameter sets)
 *    - 300KB+: 0% success rate (complete failure)
 * 
 * 2. Softcard Preload Requirement:
 *    For softcard slots, you must preload the softcard before running:
 * 
 *      preload -s <SoftcardName> .\mldsa_benchmark.exe
 * 
 *    Example:
 *      preload -s TestSoftcard .\mldsa_benchmark.exe
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
const size_t NUM_ITERATIONS = 100;

// File sizes to test (in bytes) - Based on empirical nShield HSM testing
const std::vector<size_t> FILE_SIZES = {
    1 * 1024,           // 1 KB  - Confirmed: 100% success
    10 * 1024,          // 10 KB - Confirmed: 100% success
    100 * 1024,         // 100 KB - Confirmed: 100% success
    200 * 1024,         // 200 KB - Confirmed: 100% success (HARD LIMIT)
    300 * 1024          // 300 KB - Confirmed: 0% success (FAILS)
};
const std::vector<std::string> FILE_SIZE_NAMES = {"1KB", "10KB", "100KB", "200KB", "300KB"};

// PKCS#11 function list
CK_FUNCTION_LIST_PTR pFunctionList = NULL;

// ML-DSA parameter set information
struct MLDSAParameterSet {
    CK_ULONG parameterSet;
    std::string name;
    std::string description;
    int nistLevel;
    int expectedPublicKeySize;
    int expectedSignatureSize;
    std::string securityEquivalent;
};

// Slot information
struct SlotInfo {
    CK_SLOT_ID slotId;
    std::string slotDescription;
    std::string tokenLabel;
    bool hasToken;
    bool supportsMLDSA;
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

// Helper function to get mechanism name for logging
std::string getMechanismName(CK_MECHANISM_TYPE mechanism) {
    switch (mechanism) {
        case CKM_ML_DSA: return "CKM_ML_DSA";
        default: return "Unknown";
    }
}

// Test results for all combinations
std::map<CK_SLOT_ID, std::map<std::string, std::map<std::string, BenchmarkResult>>> benchmarkResults;

std::vector<MLDSAParameterSet> getMLDSAParameterSets() {
    return {
        {CKP_ML_DSA_44, "ML-DSA-44", "Fast, compact signatures", 2, 1312, 2420, "AES-128"},
        {CKP_ML_DSA_65, "ML-DSA-65", "Balanced performance", 3, 1952, 3309, "AES-192"},
        {CKP_ML_DSA_87, "ML-DSA-87", "Maximum security", 5, 2592, 4627, "AES-256"}
    };
}

bool initializePKCS11() {
    std::cout << "ML-DSA Performance Benchmark Suite" << std::endl;
    std::cout << "====================================================" << std::endl;
    std::cout << "Benchmarking ML-DSA across multiple file sizes and parameter sets" << std::endl;   
    std::cout << "ML-DSA uses one-shot signing (entire message processed at once)" << std::endl;
    std::cout << "File sizes: ";
    for (size_t i = 0; i < FILE_SIZE_NAMES.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << FILE_SIZE_NAMES[i];
    }
    std::cout << std::endl;
    std::cout << "Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87" << std::endl;
    std::cout << "Iterations per test: Adaptive (100 for small files, reduced for large files)" << std::endl;
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
            
            // Check if slot supports ML-DSA (look for mechanisms)
            CK_ULONG mechanismCount = 0;
            rv = pFunctionList->C_GetMechanismList(slotList[i], NULL, &mechanismCount);
            if (rv == CKR_OK && mechanismCount > 0) {
                std::vector<CK_MECHANISM_TYPE> mechanisms(mechanismCount);
                rv = pFunctionList->C_GetMechanismList(slotList[i], mechanisms.data(), &mechanismCount);
                
                slotInfo.supportsMLDSA = false;
                for (CK_ULONG j = 0; j < mechanismCount; j++) {
                    if (mechanisms[j] == CKM_ML_DSA || mechanisms[j] == CKM_ML_DSA_KEY_PAIR_GEN) {
                        slotInfo.supportsMLDSA = true;
                        break;
                    }
                }
            }
        } else {
            slotInfo.hasToken = false;
            slotInfo.supportsMLDSA = false;
        }
        
        std::cout << "  Slot " << slotList[i] << ": " << slotInfo.slotDescription 
                  << " (Token: " << (slotInfo.hasToken ? slotInfo.tokenLabel : "None")
                  << ", ML-DSA: " << (slotInfo.supportsMLDSA ? "Yes" : "No") << ")" << std::endl;
        
        slots.push_back(slotInfo);
    }
    
    return slots;
}

std::vector<CK_BYTE> generateTestData(size_t size) {
    std::cout << "Generating test data (" << (size >= 1024*1024 ? size / (1024 * 1024) : 
                                               size >= 1024 ? size / 1024 : size)
              << (size >= 1024*1024 ? "MB" : size >= 1024 ? "KB" : "B") << ")..." << std::endl;
    
    // Check for HSM memory limitations with large files
    if (size > 1024 * 1024) { // > 1MB
        std::cout << "  NOTE: Large files (>1MB) may exceed HSM memory limits." << std::endl;
        std::cout << "  ML-DSA requires processing entire message at once (one-shot algorithm)." << std::endl;
    }
    
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

BenchmarkResult benchmarkMLDSAOnSlot(const SlotInfo& slotInfo, const MLDSAParameterSet& paramSet, 
                                     const std::vector<CK_BYTE>& testData, const std::string& fileSizeName) {
    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "Benchmarking " << paramSet.name << " with " << fileSizeName << " data on Slot " 
              << slotInfo.slotId << " (" << slotInfo.slotDescription << ")..." << std::endl;
    
    BenchmarkResult result;
    result.slotId = slotInfo.slotId;
    result.slotDescription = slotInfo.slotDescription;
    result.signTimes.reserve(NUM_ITERATIONS);
    result.verifyTimes.reserve(NUM_ITERATIONS);
    result.successfulIterations = 0;
    result.keyGenTimeMs = 0.0;
    result.avgSignTimeMs = 0.0;
    result.avgVerifyTimeMs = 0.0;
    result.signatureSize = 0;  // Initialize to 0
    
    // Open session
    CK_SESSION_HANDLE hSession;
    CK_RV rv = pFunctionList->C_OpenSession(slotInfo.slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        std::cerr << "Error: Could not open session on slot " << slotInfo.slotId 
                  << " (error 0x" << std::hex << rv << std::dec << ")" << std::endl;
        return result;
    }
    
    // Determine if this is likely a card slot based on slot description
    bool isCardSlot = (slotInfo.slotDescription.find("card") != std::string::npos) ||
                      (slotInfo.slotDescription.find("Card") != std::string::npos) ||
                      (slotInfo.tokenLabel.find("card") != std::string::npos) ||
                      (slotInfo.tokenLabel.find("Card") != std::string::npos);
    
    // For card slots, try to login as user 
    if (isCardSlot) {
        std::cout << "  Attempting login to card slot..." << std::endl;
        rv = pFunctionList->C_Login(hSession, CKU_USER, NULL, 0); // Try with no PIN first
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            std::cout << "  Login failed (error 0x" << std::hex << rv << std::dec << "), continuing without login..." << std::endl;
            // Continue - some operations might still work
        } else if (rv == CKR_OK) {
            std::cout << "  Login successful" << std::endl;
        }
    }
    
    // === Key Generation Benchmark ===
    CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;
    
    // Setup key generation parameters
    // For card slots, sensitive/non-extractable keys must be stored on token (CKA_TOKEN = TRUE)
    // For accelerator slots, we can use session keys (CKA_TOKEN = FALSE)
    CK_ULONG keyType = CKK_ML_DSA;
    CK_ML_DSA_PARAMETER_SET_TYPE parameterSetValue = static_cast<CK_ML_DSA_PARAMETER_SET_TYPE>(paramSet.parameterSet);
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;

    std::string pubLabel = paramSet.name + "-Bench-Public-" + std::to_string(slotInfo.slotId);
    std::string privLabel = paramSet.name + "-Bench-Private-" + std::to_string(slotInfo.slotId);

    std::cout << "  Slot type detected: " << (isCardSlot ? "Card slot" : "Accelerator slot") << std::endl;

    // Try multiple template configurations for better compatibility
    CK_MECHANISM mechanism = {CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0};
    bool keyGenSuccess = false;
    
    // Configuration 1: Try session keys first (works for accelerator slots)
    if (!keyGenSuccess) {
        std::cout << "  Attempting key generation with session keys..." << std::endl;
        
        CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_VERIFY, &ckTrue, sizeof(ckTrue)},
            {CKA_TOKEN, &ckFalse, sizeof(ckFalse)}, // Session keys
            {CKA_LABEL, (CK_VOID_PTR)pubLabel.c_str(), static_cast<CK_ULONG>(pubLabel.size())},
            {CKA_PARAMETER_SET, &parameterSetValue, sizeof(parameterSetValue)}
        };

        CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_CLASS, &privKeyClass, sizeof(privKeyClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_SIGN, &ckTrue, sizeof(ckTrue)},
            {CKA_TOKEN, &ckFalse, sizeof(ckFalse)}, // Session keys
            {CKA_LABEL, (CK_VOID_PTR)privLabel.c_str(), static_cast<CK_ULONG>(privLabel.size())},
            {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
            {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)}, // Non-sensitive for session keys
            {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)}, // Extractable for session keys
            {CKA_PARAMETER_SET, &parameterSetValue, sizeof(parameterSetValue)}
        };
        
        // Measure key generation time
        auto keyGenStart = std::chrono::high_resolution_clock::now();
        rv = pFunctionList->C_GenerateKeyPair(
            hSession,
            &mechanism,
            publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(publicKeyTemplate[0]),
            privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(privateKeyTemplate[0]),
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
    
    // Configuration 2: Try token keys for card slots
    if (!keyGenSuccess && isCardSlot) {
        std::cout << "  Attempting key generation with token keys..." << std::endl;
        
        CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_VERIFY, &ckTrue, sizeof(ckTrue)},
            {CKA_TOKEN, &ckTrue, sizeof(ckTrue)}, // Token keys
            {CKA_LABEL, (CK_VOID_PTR)pubLabel.c_str(), static_cast<CK_ULONG>(pubLabel.size())},
            {CKA_PARAMETER_SET, &parameterSetValue, sizeof(parameterSetValue)}
        };

        CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_CLASS, &privKeyClass, sizeof(privKeyClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_SIGN, &ckTrue, sizeof(ckTrue)},
            {CKA_TOKEN, &ckTrue, sizeof(ckTrue)}, // Store on token for card slots
            {CKA_LABEL, (CK_VOID_PTR)privLabel.c_str(), static_cast<CK_ULONG>(privLabel.size())},
            {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
            {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
            {CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)},
            {CKA_PARAMETER_SET, &parameterSetValue, sizeof(parameterSetValue)}
        };

        // Measure key generation time
        auto keyGenStart = std::chrono::high_resolution_clock::now();
        rv = pFunctionList->C_GenerateKeyPair(
            hSession,
            &mechanism,
            publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(publicKeyTemplate[0]),
            privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(privateKeyTemplate[0]),
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

    if (!keyGenSuccess) {
        std::cerr << "Key generation failed for " << paramSet.name 
                  << " on slot " << slotInfo.slotId << " (error 0x" << std::hex << rv << std::dec << ")" << std::endl;
        pFunctionList->C_CloseSession(hSession);
        return result;
    }
    
    // === Signing and Verification Benchmark ===
    // Use standard ML-DSA mechanism for files ≤100KB
    CK_MECHANISM signMechanism = {CKM_ML_DSA, NULL, 0};
    
    std::cout << "  Using CKM_ML_DSA for file size " 
              << (testData.size() >= 1024*1024 ? std::to_string(testData.size() / (1024*1024)) + "MB" :
                  testData.size() >= 1024 ? std::to_string(testData.size() / 1024) + "KB" :
                  std::to_string(testData.size()) + "B") << std::endl;
    
    // Allocate generous signature buffer to handle ML-DSA signature size variations
    // ML-DSA signatures can be up to ~100KB, so we'll allocate 128KB to be safe
    const CK_ULONG maxSignatureSize = 131072; // 128KB buffer
    std::vector<CK_BYTE> signature(maxSignatureSize);
    
    std::cout << "  Running " << NUM_ITERATIONS << " sign/verify cycles..." << std::endl;
    
    // Progress indicator
    const size_t progressStep = NUM_ITERATIONS / 10;
    
    for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
        if (i % progressStep == 0) {
            std::cout << "    Progress: " << (i * 100 / NUM_ITERATIONS) << "%" << std::endl;
        }
        
        
        
        // === Signing ===
        rv = pFunctionList->C_SignInit(hSession, &signMechanism, hPrivateKey);
        if (rv != CKR_OK) {
            std::cerr << "    Sign init failed (iteration " << i << ", error 0x" << std::hex << rv << std::dec << ")" << std::endl;
            continue;
        }
        
        CK_ULONG actualSigLen = maxSignatureSize;
        auto signStart = std::chrono::high_resolution_clock::now();
        rv = pFunctionList->C_Sign(hSession, const_cast<CK_BYTE*>(testData.data()), 
                                  static_cast<CK_ULONG>(testData.size()), 
                                  signature.data(), &actualSigLen);
        auto signEnd = std::chrono::high_resolution_clock::now();
        
        if (rv != CKR_OK) {
            std::cerr << "    Signing failed (iteration " << i << ", error 0x" << std::hex << rv << std::dec << ")" << std::endl;
            continue;
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
        rv = pFunctionList->C_Verify(hSession, const_cast<CK_BYTE*>(testData.data()),
                                    static_cast<CK_ULONG>(testData.size()),
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
        // NOTE: ML-DSA signature size is constant per parameter set regardless of message size
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
    
    std::cout << "  Completed: " << result.successfulIterations << "/" << NUM_ITERATIONS 
              << " successful sign/verify cycles" << std::endl;
    
    // Clean up
    pFunctionList->C_CloseSession(hSession);
    
    return result;
}

void printBenchmarkTable(const std::vector<SlotInfo>& slots) {
    std::cout << "\n" << std::string(150, '=') << std::endl;
    std::cout << "ML-DSA BENCHMARK RESULTS" << std::endl;
    std::cout << std::string(150, '=') << std::endl;
    
    for (const auto& slot : slots) {
        if (!slot.supportsMLDSA) continue;
        
        std::cout << "\nSLOT " << slot.slotId << ": " << slot.slotDescription 
                  << " (Token: " << slot.tokenLabel << ")" << std::endl;
        std::cout << std::string(150, '-') << std::endl;
        std::cout << "NOTE: ML-DSA signature size is constant per parameter set, independent of message size" << std::endl;
        std::cout << "All times in milliseconds. SigSize = ML-DSA signature size in bytes." << std::endl;
        std::cout << std::string(150, '-') << std::endl;
        
        // Table header
        std::cout << std::left << std::setw(12) << "Param Set"
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
        std::cout << std::string(150, '-') << std::endl;
        
        // Data rows
        for (const auto& paramSet : getMLDSAParameterSets()) {
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
        std::cout << std::string(150, '-') << std::endl;
    }
    
    // Summary statistics
    std::cout << "\nSUMMARY STATISTICS" << std::endl;
    std::cout << std::string(80, '=') << std::endl;
    
    for (const auto& paramSet : getMLDSAParameterSets()) {
        std::cout << "\n" << paramSet.name << " (" << paramSet.description << "):" << std::endl;
        std::cout << "  NIST Security Level: " << paramSet.nistLevel << std::endl;
        std::cout << "  Security Equivalent: " << paramSet.securityEquivalent << std::endl;
        std::cout << "  Expected Signature Size: " << paramSet.expectedSignatureSize << " bytes" << std::endl;
        
        // Average performance across all slots and file sizes
        double totalKeyGen = 0.0, totalSign = 0.0, totalVerify = 0.0;
        int count = 0;
        
        for (const auto& slot : slots) {
            if (!slot.supportsMLDSA) continue;
            
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
    
    std::cout << "\nBENCHMARK CONFIGURATION" << std::endl;
    std::cout << std::string(40, '=') << std::endl;
    std::cout << "Iterations per test: " << NUM_ITERATIONS << std::endl;
    std::cout << "File sizes tested: ";
    for (size_t i = 0; i < FILE_SIZE_NAMES.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << FILE_SIZE_NAMES[i];
    }
    std::cout << std::endl;
    std::cout << "Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87" << std::endl;
    std::cout << "Keys: Session-only (not stored in token)" << std::endl;
    std::cout << "PKCS#11 Library: cknfast.dll (nShield)" << std::endl;
    std::cout << "NOTE: Large files (>1MB) may fail due to ML-DSA one-shot limitation (no hashing before signing)" << std::endl;
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
    
    // Filter slots that support ML-DSA
    std::vector<SlotInfo> mldsa_slots;
    for (const auto& slot : slots) {
        if (slot.supportsMLDSA) {
            mldsa_slots.push_back(slot);
        }
    }
    
    if (mldsa_slots.empty()) {
        std::cerr << "No slots support ML-DSA. Please check firmware version and capabilities." << std::endl;
        return -1;
    }
    
    std::cout << "\nFound " << mldsa_slots.size() << " slot(s) supporting ML-DSA:" << std::endl;
    for (const auto& slot : mldsa_slots) {
        std::cout << "  Slot " << slot.slotId << ": " << slot.slotDescription 
                  << " (Token: " << slot.tokenLabel << ")" << std::endl;
    }
    
    auto parameterSets = getMLDSAParameterSets();
    
    // Run benchmarks for each combination
    for (size_t fileIdx = 0; fileIdx < FILE_SIZES.size(); ++fileIdx) {
        const auto& fileSize = FILE_SIZES[fileIdx];
        const auto& fileSizeName = FILE_SIZE_NAMES[fileIdx];
        
        std::cout << "\n" << std::string(80, '=') << std::endl;
        std::cout << "TESTING FILE SIZE: " << fileSizeName << std::endl;
        std::cout << std::string(80, '=') << std::endl;
        
        // Generate test data for this file size
        auto testData = generateTestData(fileSize);
        
        // Test each ML-DSA enabled slot
        for (const auto& slot : mldsa_slots) {
            std::cout << "\n+++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
            std::cout << "Testing Slot " << slot.slotId << ": " << slot.slotDescription << std::endl;
            std::cout << "+++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
            
            // Test each parameter set with this file size on this slot
            for (const auto& paramSet : parameterSets) {
                auto result = benchmarkMLDSAOnSlot(slot, paramSet, testData, fileSizeName);
                benchmarkResults[slot.slotId][paramSet.name][fileSizeName] = result;
            }
        }
    }
    
    // Print comprehensive results table
    printBenchmarkTable(mldsa_slots);
    
    // Cleanup PKCS#11
    std::cout << "\nCleaning up PKCS#11..." << std::endl;
    if (pFunctionList) {
        pFunctionList->C_Finalize(NULL);
    }
    
    std::cout << "\nBenchmark completed successfully!" << std::endl;
    std::cout << "PKCS#11 performance data captured from " << mldsa_slots.size() 
              << " HSM slot(s)." << std::endl;
    
    return 0;
}
