/*
 * ML-DSA Performance Benchmark with SHA-256 Hashing using PKCS#11 with nShield HSM
 * 
 * This application benchmarks ML-DSA (Module-Lattice Digital Signature Algorithm) 
 * performance using hash-then-sign approach:
 * - File sizes: 1KB, 100KB, 500KB, 1MB
 * - Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87
 * - Process: SHA-256 hash --> ML-DSA sign hash --> ML-DSA verify hash
 * - Shows hash values and signature sizes to user
 * - Tests all available HSM slots
 * - 100 iterations per test for statistical accuracy
 * 
 * BENEFITS OF HASH-THEN-SIGN APPROACH:
 * - No file size limitations (hash is always 32 bytes)
 * - Better performance for large files
 * - Standard cryptographic practice
 * - Reduced HSM memory usage
 *
 * DIRECT SIGNING vs HASH-THEN-SIGN
 * - Direct Signing: Sign the file directly (not recommended for large files)
 * - Hash-Then-Sign: Hash the file first, then sign the hash (recommended)
 *
 * IMPORTANT: nCipher nShield Usage Requirements
 * ============================================
 * 
 * For softcard slots, you must preload the softcard before running:
 * 
 *     preload -s <SoftcardName> .\mldsa_benchmark_hash.exe
 * 
 * Example:
 *     preload -s TestSoftcard .\mldsa_benchmark_hash.exe
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

// File sizes to test (in bytes) - Extended range since we're using hash-then-sign
const std::vector<size_t> FILE_SIZES = {
    1 * 1024,           // 1 KB
    100 * 1024,         // 100 KB
    500 * 1024,         // 500 KB
    1024 * 1024         // 1 MB
};

// Common file sizes (DLL)
const std::vector<std::string> FILE_SIZE_NAMES = {"1KB", "100KB", "500KB", "1MB"};

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
    bool supportsSHA256;
};

// Benchmark results structure
struct BenchmarkResult {
    double keyGenTimeMs;
    double avgHashTimeMs;
    double avgSignTimeMs;
    double avgVerifyTimeMs;
    size_t signatureSize;
    std::vector<double> hashTimes;
    std::vector<double> signTimes;
    std::vector<double> verifyTimes;
    int successfulIterations;
    CK_SLOT_ID slotId;
    std::string slotDescription;
    std::string firstHashHex;        // First hash value (for display)
    std::string firstSignatureHex;   // First signature (truncated for display)
};

// Test results for all combinations
std::map<CK_SLOT_ID, std::map<std::string, std::map<std::string, BenchmarkResult>>> benchmarkResults;

std::vector<MLDSAParameterSet> getMLDSAParameterSets() {
    return {
        {CKP_ML_DSA_44, "ML-DSA-44", "Fast, compact signatures", 2, 1312, 2420, "AES-128"},
        {CKP_ML_DSA_65, "ML-DSA-65", "Balanced performance", 3, 1952, 3309, "AES-192"},
        {CKP_ML_DSA_87, "ML-DSA-87", "Maximum security", 5, 2592, 4627, "AES-256"}
    };
}

// Convert byte array to hex string
std::string bytesToHex(const std::vector<CK_BYTE>& bytes, size_t maxLen = 0) {
    std::ostringstream oss;
    size_t len = (maxLen > 0 && maxLen < bytes.size()) ? maxLen : bytes.size();
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(bytes[i]);
    }
    if (maxLen > 0 && maxLen < bytes.size()) {
        oss << "...";
    }
    return oss.str();
}

bool initializePKCS11() {
    std::cout << "ML-DSA Hash-then-Sign Performance Benchmark Suite" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << "Benchmarking ML-DSA with SHA-256 hash-then-sign approach" << std::endl;   
    std::cout << "Process: File --> SHA-256 Hash (32 bytes) --> ML-DSA Sign --> ML-DSA Verify" << std::endl;
    std::cout << "File sizes: ";
    for (size_t i = 0; i < FILE_SIZE_NAMES.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << FILE_SIZE_NAMES[i];
    }
    std::cout << std::endl;
    std::cout << "Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87" << std::endl;
    std::cout << "Iterations per test: " << NUM_ITERATIONS << std::endl;
    std::cout << "Benefits: No file size limits, better large file performance" << std::endl;
    std::cout << "========================================================\n" << std::endl;
    
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
            
            // Check if slot supports ML-DSA and SHA-256
            CK_ULONG mechanismCount = 0;
            rv = pFunctionList->C_GetMechanismList(slotList[i], NULL, &mechanismCount);
            if (rv == CKR_OK && mechanismCount > 0) {
                std::vector<CK_MECHANISM_TYPE> mechanisms(mechanismCount);
                rv = pFunctionList->C_GetMechanismList(slotList[i], mechanisms.data(), &mechanismCount);
                
                slotInfo.supportsMLDSA = false;
                slotInfo.supportsSHA256 = false;
                for (CK_ULONG j = 0; j < mechanismCount; j++) {
                    if (mechanisms[j] == CKM_ML_DSA || mechanisms[j] == CKM_ML_DSA_KEY_PAIR_GEN) {
                        slotInfo.supportsMLDSA = true;
                    }
                    if (mechanisms[j] == CKM_SHA256) {
                        slotInfo.supportsSHA256 = true;
                    }
                }
            }
        } else {
            slotInfo.hasToken = false;
            slotInfo.supportsMLDSA = false;
            slotInfo.supportsSHA256 = false;
        }
        
        std::cout << "  Slot " << slotList[i] << ": " << slotInfo.slotDescription 
                  << " (Token: " << (slotInfo.hasToken ? slotInfo.tokenLabel : "None")
                  << ", ML-DSA: " << (slotInfo.supportsMLDSA ? "Yes" : "No")
                  << ", SHA-256: " << (slotInfo.supportsSHA256 ? "Yes" : "No") << ")" << std::endl;
        
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

std::vector<CK_BYTE> computeSHA256Hash(CK_SESSION_HANDLE hSession, const std::vector<CK_BYTE>& data, double& hashTimeMs) {
    CK_MECHANISM hashMechanism = {CKM_SHA256, NULL, 0};
    std::vector<CK_BYTE> hash(32); // SHA-256 produces 32-byte hash
    CK_ULONG hashLen = 32;
    
    auto hashStart = std::chrono::high_resolution_clock::now();
    
    CK_RV rv = pFunctionList->C_DigestInit(hSession, &hashMechanism);
    if (rv != CKR_OK) {
        throw std::runtime_error("SHA-256 digest init failed");
    }
    
    rv = pFunctionList->C_Digest(hSession, const_cast<CK_BYTE*>(data.data()), 
                                static_cast<CK_ULONG>(data.size()), hash.data(), &hashLen);
    if (rv != CKR_OK) {
        throw std::runtime_error("SHA-256 digest failed");
    }
    
    auto hashEnd = std::chrono::high_resolution_clock::now();
    hashTimeMs = std::chrono::duration<double, std::milli>(hashEnd - hashStart).count();
    
    return hash;
}

BenchmarkResult benchmarkMLDSAHashSignOnSlot(const SlotInfo& slotInfo, const MLDSAParameterSet& paramSet, 
                                             const std::vector<CK_BYTE>& testData, const std::string& fileSizeName) {
    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "Benchmarking " << paramSet.name << " with " << fileSizeName << " data on Slot " 
              << slotInfo.slotId << " (" << slotInfo.slotDescription << ")..." << std::endl;
    
    BenchmarkResult result;
    result.slotId = slotInfo.slotId;
    result.slotDescription = slotInfo.slotDescription;
    result.hashTimes.reserve(NUM_ITERATIONS);
    result.signTimes.reserve(NUM_ITERATIONS);
    result.verifyTimes.reserve(NUM_ITERATIONS);
    result.successfulIterations = 0;
    result.keyGenTimeMs = 0.0;
    result.avgHashTimeMs = 0.0;
    result.avgSignTimeMs = 0.0;
    result.avgVerifyTimeMs = 0.0;
    result.signatureSize = 0;
    
    // Check if slot supports both ML-DSA and SHA-256
    if (!slotInfo.supportsMLDSA) {
        std::cerr << "Error: Slot does not support ML-DSA" << std::endl;
        return result;
    }
    if (!slotInfo.supportsSHA256) {
        std::cerr << "Error: Slot does not support SHA-256" << std::endl;
        return result;
    }
    
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
        } else if (rv == CKR_OK) {
            std::cout << "  Login successful" << std::endl;
        }
    }
    
    // === Key Generation Benchmark ===
    CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;
    
    // Setup key generation parameters
    CK_ULONG keyType = CKK_ML_DSA;
    CK_ML_DSA_PARAMETER_SET_TYPE parameterSetValue = static_cast<CK_ML_DSA_PARAMETER_SET_TYPE>(paramSet.parameterSet);
    CK_BBOOL ckTrue = CK_TRUE;
    CK_BBOOL ckFalse = CK_FALSE;
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;

    std::string pubLabel = paramSet.name + "-Hash-Public-" + std::to_string(slotInfo.slotId);
    std::string privLabel = paramSet.name + "-Hash-Private-" + std::to_string(slotInfo.slotId);

    std::cout << "  Slot type detected: " << (isCardSlot ? "Card slot" : "Accelerator slot") << std::endl;

    CK_MECHANISM mechanism = {CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0};
    bool keyGenSuccess = false;
    
    // Try session keys first
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
            {CKA_SENSITIVE, &ckFalse, sizeof(ckFalse)},
            {CKA_EXTRACTABLE, &ckTrue, sizeof(ckTrue)},
            {CKA_PARAMETER_SET, &parameterSetValue, sizeof(parameterSetValue)}
        };
        
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
    
    // Try token keys for card slots if session keys failed
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
            {CKA_TOKEN, &ckTrue, sizeof(ckTrue)},
            {CKA_LABEL, (CK_VOID_PTR)privLabel.c_str(), static_cast<CK_ULONG>(privLabel.size())},
            {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)},
            {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)},
            {CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)},
            {CKA_PARAMETER_SET, &parameterSetValue, sizeof(parameterSetValue)}
        };

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
    
    // === Hash-then-Sign Benchmark ===
    CK_MECHANISM signMechanism = {CKM_ML_DSA, NULL, 0};

    std::cout << "  Process: File (" << fileSizeName << ") --> SHA-256 Hash (32 bytes) --> ML-DSA Sign --> ML-DSA Verify" << std::endl;

    // Allocate signature buffer
    const CK_ULONG maxSignatureSize = 131072; // 128KB buffer
    std::vector<CK_BYTE> signature(maxSignatureSize);
    
    std::cout << "  Running " << NUM_ITERATIONS << " hash-sign-verify cycles..." << std::endl;
    
    // Progress indicator
    const size_t progressStep = NUM_ITERATIONS / 10;
    
    for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
        if (i % progressStep == 0) {
            std::cout << "    Progress: " << (i * 100 / NUM_ITERATIONS) << "%" << std::endl;
        }
        
        try {
            // === Step 1: Hash the data ===
            double hashTimeMs = 0.0;
            auto hash = computeSHA256Hash(hSession, testData, hashTimeMs);
            result.hashTimes.push_back(hashTimeMs);
            
            // Store first hash for display
            if (i == 0) {
                result.firstHashHex = bytesToHex(hash);
                std::cout << "    SHA-256 Hash: " << result.firstHashHex << std::endl;
            }
            
            // === Step 2: Sign the hash ===
            rv = pFunctionList->C_SignInit(hSession, &signMechanism, hPrivateKey);
            if (rv != CKR_OK) {
                std::cerr << "    Sign init failed (iteration " << i << ", error 0x" << std::hex << rv << std::dec << ")" << std::endl;
                continue;
            }
            
            CK_ULONG actualSigLen = maxSignatureSize;
            auto signStart = std::chrono::high_resolution_clock::now();
            rv = pFunctionList->C_Sign(hSession, hash.data(), static_cast<CK_ULONG>(hash.size()), 
                                      signature.data(), &actualSigLen);
            auto signEnd = std::chrono::high_resolution_clock::now();
            
            if (rv != CKR_OK) {
                std::cerr << "    Signing failed (iteration " << i << ", error 0x" << std::hex << rv << std::dec << ")" << std::endl;
                continue;
            }
            
            double signTimeMs = std::chrono::duration<double, std::milli>(signEnd - signStart).count();
            result.signTimes.push_back(signTimeMs);
            
            // Store first signature for display
            if (i == 0) {
                std::vector<CK_BYTE> sigVec(signature.begin(), signature.begin() + actualSigLen);
                result.firstSignatureHex = bytesToHex(sigVec, 32); // Show first 32 bytes
                std::cout << "    ML-DSA Signature: " << result.firstSignatureHex << " (size: " << actualSigLen << " bytes)" << std::endl;
            }
            
            // === Step 3: Verify the signature ===
            rv = pFunctionList->C_VerifyInit(hSession, &signMechanism, hPublicKey);
            if (rv != CKR_OK) {
                std::cerr << "    Verify init failed (iteration " << i << ", error 0x" << std::hex << rv << std::dec << ")" << std::endl;
                continue;
            }
            
            auto verifyStart = std::chrono::high_resolution_clock::now();
            rv = pFunctionList->C_Verify(hSession, hash.data(), static_cast<CK_ULONG>(hash.size()),
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
            
        } catch (const std::exception& e) {
            std::cerr << "    Exception in iteration " << i << ": " << e.what() << std::endl;
            continue;
        }
    }
    
    // Calculate averages
    if (!result.hashTimes.empty()) {
        result.avgHashTimeMs = std::accumulate(result.hashTimes.begin(), result.hashTimes.end(), 0.0) / result.hashTimes.size();
    }
    if (!result.signTimes.empty()) {
        result.avgSignTimeMs = std::accumulate(result.signTimes.begin(), result.signTimes.end(), 0.0) / result.signTimes.size();
    }
    if (!result.verifyTimes.empty()) {
        result.avgVerifyTimeMs = std::accumulate(result.verifyTimes.begin(), result.verifyTimes.end(), 0.0) / result.verifyTimes.size();
    }
    
    std::cout << "  Completed: " << result.successfulIterations << "/" << NUM_ITERATIONS 
              << " successful hash-sign-verify cycles" << std::endl;
    std::cout << "  Average times: Hash=" << std::fixed << std::setprecision(3) << result.avgHashTimeMs 
              << "ms, Sign=" << result.avgSignTimeMs << "ms, Verify=" << result.avgVerifyTimeMs << "ms" << std::endl;
    
    // Clean up
    pFunctionList->C_CloseSession(hSession);
    
    return result;
}

void printBenchmarkTable(const std::vector<SlotInfo>& slots) {
    std::cout << "\n" << std::string(180, '=') << std::endl;
    std::cout << "ML-DSA HASH-THEN-SIGN BENCHMARK RESULTS" << std::endl;
    std::cout << std::string(180, '=') << std::endl;
    
    for (const auto& slot : slots) {
        if (!slot.supportsMLDSA || !slot.supportsSHA256) continue;
        
        std::cout << "\nSLOT " << slot.slotId << ": " << slot.slotDescription 
                  << " (Token: " << slot.tokenLabel << ")" << std::endl;
        std::cout << std::string(180, '-') << std::endl;
        std::cout << "Process: File --> SHA-256 Hash (32 bytes) --> ML-DSA Sign --> ML-DSA Verify" << std::endl;
        std::cout << "All times in milliseconds. Hash time increases with file size, Sign/Verify time constant (32-byte input)" << std::endl;
        std::cout << std::string(180, '-') << std::endl;
        
        // Table header
        std::cout << std::left << std::setw(12) << "Param Set"
                  << std::setw(10) << "File Size"
                  << std::setw(12) << "KeyGen"
                  << std::setw(12) << "AvgHash"
                  << std::setw(12) << "MinSign"
                  << std::setw(12) << "MaxSign"
                  << std::setw(12) << "AvgSign"
                  << std::setw(12) << "MinVerify"
                  << std::setw(12) << "MaxVerify"
                  << std::setw(12) << "AvgVerify"
                  << std::setw(13) << "SuccessRate"
                  << std::setw(10) << "SigSize"
                  << std::setw(20) << "Hash (first 16 hex)" << std::endl;
        std::cout << std::string(180, '-') << std::endl;
        
        // Data rows
        for (const auto& paramSet : getMLDSAParameterSets()) {
            for (size_t i = 0; i < FILE_SIZE_NAMES.size(); ++i) {
                const auto& fileSizeName = FILE_SIZE_NAMES[i];
                const auto& result = benchmarkResults[slot.slotId][paramSet.name][fileSizeName];
                
                double minSign = result.signTimes.empty() ? 0.0 : *std::min_element(result.signTimes.begin(), result.signTimes.end());
                double maxSign = result.signTimes.empty() ? 0.0 : *std::max_element(result.signTimes.begin(), result.signTimes.end());
                double minVerify = result.verifyTimes.empty() ? 0.0 : *std::min_element(result.verifyTimes.begin(), result.verifyTimes.end());
                double maxVerify = result.verifyTimes.empty() ? 0.0 : *std::max_element(result.verifyTimes.begin(), result.verifyTimes.end());
                
                std::string hashDisplay = result.firstHashHex.length() > 32 ? result.firstHashHex.substr(0, 32) : result.firstHashHex;
                
                std::cout << std::left << std::setw(12) << paramSet.name
                          << std::setw(10) << fileSizeName
                          << std::setw(12) << std::fixed << std::setprecision(3) << result.keyGenTimeMs
                          << std::setw(12) << std::fixed << std::setprecision(3) << result.avgHashTimeMs
                          << std::setw(12) << std::fixed << std::setprecision(3) << minSign
                          << std::setw(12) << std::fixed << std::setprecision(3) << maxSign
                          << std::setw(12) << std::fixed << std::setprecision(3) << result.avgSignTimeMs
                          << std::setw(12) << std::fixed << std::setprecision(3) << minVerify
                          << std::setw(12) << std::fixed << std::setprecision(3) << maxVerify
                          << std::setw(12) << std::fixed << std::setprecision(3) << result.avgVerifyTimeMs
                          << std::setw(13) << std::fixed << std::setprecision(1) 
                          << (static_cast<double>(result.successfulIterations) / NUM_ITERATIONS * 100.0)
                          << std::setw(10) << result.signatureSize
                          << std::setw(20) << hashDisplay << std::endl;
            }
        }
        std::cout << std::string(180, '-') << std::endl;
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
        double totalKeyGen = 0.0, totalHash = 0.0, totalSign = 0.0, totalVerify = 0.0;
        int count = 0;
        
        for (const auto& slot : slots) {
            if (!slot.supportsMLDSA || !slot.supportsSHA256) continue;
            
            for (const auto& fileSizeName : FILE_SIZE_NAMES) {
                const auto& result = benchmarkResults[slot.slotId][paramSet.name][fileSizeName];
                if (result.successfulIterations > 0) {
                    totalKeyGen += result.keyGenTimeMs;
                    totalHash += result.avgHashTimeMs;
                    totalSign += result.avgSignTimeMs;
                    totalVerify += result.avgVerifyTimeMs;
                    count++;
                }
            }
        }
        
        if (count > 0) {
            std::cout << "  Average Key Generation Time: " << std::fixed << std::setprecision(3) << (totalKeyGen / count) << " ms" << std::endl;
            std::cout << "  Average Hash Time: " << std::fixed << std::setprecision(3) << (totalHash / count) << " ms" << std::endl;
            std::cout << "  Average Signing Time: " << std::fixed << std::setprecision(3) << (totalSign / count) << " ms" << std::endl;
            std::cout << "  Average Verification Time: " << std::fixed << std::setprecision(3) << (totalVerify / count) << " ms" << std::endl;
        }
    }
    
    std::cout << "\nBENCHMARK CONFIGURATION" << std::endl;
    std::cout << std::string(50, '=') << std::endl;
    std::cout << "Approach: Hash-then-Sign (SHA-256 + ML-DSA)" << std::endl;
    std::cout << "Iterations per test: " << NUM_ITERATIONS << std::endl;
    std::cout << "File sizes tested: ";
    for (size_t i = 0; i < FILE_SIZE_NAMES.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << FILE_SIZE_NAMES[i];
    }
    std::cout << std::endl;
    std::cout << "Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87" << std::endl;
    std::cout << "Hash algorithm: SHA-256 (32-byte output)" << std::endl;
    std::cout << "Keys: Session-only (not stored in token)" << std::endl;
    std::cout << "PKCS#11 Library: cknfast.dll (nShield)" << std::endl;
    std::cout << "Benefits: No file size limitations, better large file performance" << std::endl;
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
    
    // Filter slots that support both ML-DSA and SHA-256
    std::vector<SlotInfo> compatible_slots;
    for (const auto& slot : slots) {
        if (slot.supportsMLDSA && slot.supportsSHA256) {
            compatible_slots.push_back(slot);
        }
    }
    
    if (compatible_slots.empty()) {
        std::cerr << "No slots support both ML-DSA and SHA-256. Please check firmware version and capabilities." << std::endl;
        return -1;
    }
    
    std::cout << "\nFound " << compatible_slots.size() << " slot(s) supporting ML-DSA + SHA-256:" << std::endl;
    for (const auto& slot : compatible_slots) {
        std::cout << "  Slot " << slot.slotId << ": " << slot.slotDescription 
                  << " (Token: " << slot.tokenLabel << ")" << std::endl;
    }
    
    auto parameterSets = getMLDSAParameterSets();
    
    // Run benchmarks for each combination
    for (size_t fileIdx = 0; fileIdx < FILE_SIZES.size(); ++fileIdx) {
        const auto& fileSize = FILE_SIZES[fileIdx];
        const auto& fileSizeName = FILE_SIZE_NAMES[fileIdx];
        
        std::cout << "\n" << std::string(80, '=') << std::endl;
        std::cout << "TESTING FILE SIZE: " << fileSizeName << " (Hash-then-Sign)" << std::endl;
        std::cout << std::string(80, '=') << std::endl;
        
        // Generate test data for this file size
        auto testData = generateTestData(fileSize);
        
        // Test each compatible slot
        for (const auto& slot : compatible_slots) {
            std::cout << "\n+++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
            std::cout << "Testing Slot " << slot.slotId << ": " << slot.slotDescription << std::endl;
            std::cout << "+++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
            
            // Test each parameter set with this file size on this slot
            for (const auto& paramSet : parameterSets) {
                auto result = benchmarkMLDSAHashSignOnSlot(slot, paramSet, testData, fileSizeName);
                benchmarkResults[slot.slotId][paramSet.name][fileSizeName] = result;
            }
        }
    }
    
    // Print comprehensive results table
    printBenchmarkTable(compatible_slots);
    
    // Cleanup PKCS#11
    std::cout << "\nCleaning up PKCS#11..." << std::endl;
    if (pFunctionList) {
        pFunctionList->C_Finalize(NULL);
    }
    
    std::cout << "\nHash-then-Sign benchmark completed successfully!" << std::endl;
    std::cout << "PKCS#11 performance data captured from " << compatible_slots.size() 
              << " HSM slot(s)." << std::endl;
    
    return 0;
}