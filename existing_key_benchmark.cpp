#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <string>
#include <sstream> // For hex output
#include "nfast-conf.h"

// PKCS#11 includes
extern "C" {
#include "pkcs11/cryptoki.h"
}

// Helper to get hex string from CK_RV
std::string rvToHexString(CK_RV rv) {
    std::stringstream ss;
    ss << "0x" << std::uppercase << std::hex << rv;
    return ss.str();
}

// Structure to hold the benchmark results
struct BenchmarkResult {
    bool success = false;
    std::string keyLabel;
    CK_SLOT_ID slotId;
    CK_KEY_TYPE keyType;
    CK_ULONG keySize;
    double avgSignTime = 0.0;
    double avgVerifyTime = 0.0;
    size_t dataSize = 0;
    size_t signatureSize = 0;
    std::string errorMessage;
};

// Function to initialize PKCS#11
CK_FUNCTION_LIST_PTR initializePKCS11() {
    CK_FUNCTION_LIST_PTR pFunctionList = nullptr;
    CK_RV rv;

    rv = C_GetFunctionList(&pFunctionList);
    if (rv != CKR_OK || !pFunctionList) {
        std::cerr << "Failed to get PKCS#11 function list. Error: " << rvToHexString(rv) << std::endl;
        return nullptr;
    }

    rv = pFunctionList->C_Initialize(nullptr);
    if (rv != CKR_OK) {
        std::cerr << "Failed to initialize PKCS#11. Error: " << rvToHexString(rv) << std::endl;
        return nullptr;
    }

    return pFunctionList;
}

// Function to find a key by label in a specific slot
CK_OBJECT_HANDLE findKeyByLabel(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, 
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
bool getKeyAttributes(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, 
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
            std::vector<CK_BYTE> p(dsaPrimeAttr.ulValueLen); // CORRECTED
            dsaPrimeAttr.pValue = p.data();                  // CORRECTED
            rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &dsaPrimeAttr, 1);
            if (rv == CKR_OK) {
                *keySize = dsaPrimeAttr.ulValueLen * 8;      // CORRECTED
                return true;
            }
        }
    } else if (*keyType == CKK_EC) {
        // For EC, we need to get the CKA_EC_PARAMS and deduce the size
        CK_ATTRIBUTE ecParamsAttr = {CKA_EC_PARAMS, nullptr, 0};
        rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &ecParamsAttr, 1);
        if (rv == CKR_OK) {
            std::vector<CK_BYTE> ecParams(ecParamsAttr.ulValueLen); // CORRECTED
            ecParamsAttr.pValue = ecParams.data();                 // CORRECTED
            rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &ecParamsAttr, 1);
            if (rv == CKR_OK) {
                // A very simple approximation based on the length of the DER-encoded OID
                if (ecParamsAttr.ulValueLen <= 10) *keySize = 256;      // CORRECTED
                else if (ecParamsAttr.ulValueLen <= 12) *keySize = 384; // CORRECTED
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
        case CKK_ML_DSA:
            return preferHash ? CKM_ML_DSA : CKM_ML_DSA;
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

// Main benchmark logic
BenchmarkResult performKeyLookupBenchmark(CK_SLOT_ID slotId, const std::string& keyLabel, 
                                          size_t dataSize, int rounds = 100) {
    BenchmarkResult result;
    result.slotId = slotId;
    result.keyLabel = keyLabel;
    result.dataSize = dataSize;

    CK_FUNCTION_LIST_PTR pFunctionList = initializePKCS11();
    if (!pFunctionList) {
        result.errorMessage = "Failed to initialize PKCS#11";
        return result;
    }

    // Open session
    CK_SESSION_HANDLE hSession;
    CK_RV rv = pFunctionList->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
                                            nullptr, nullptr, &hSession);
    if (rv != CKR_OK) {
        result.errorMessage = "Failed to open session on slot " + std::to_string(slotId) + 
                              ". Error: " + rvToHexString(rv);
        pFunctionList->C_Finalize(nullptr);
        return result;
    }

    std::cout << "Looking for key '" << keyLabel << "' in slot " << slotId << "..." << std::endl;

    // Find private key
    CK_OBJECT_HANDLE hPrivateKey = findKeyByLabel(pFunctionList, hSession, keyLabel, CKO_PRIVATE_KEY);
    if (hPrivateKey == CK_INVALID_HANDLE) {
        result.errorMessage = "Private key '" + keyLabel + "' not found in slot " + std::to_string(slotId);
        pFunctionList->C_CloseSession(hSession);
        pFunctionList->C_Finalize(nullptr);
        return result;
    }

    // Find public key
    CK_OBJECT_HANDLE hPublicKey = findKeyByLabel(pFunctionList, hSession, keyLabel, CKO_PUBLIC_KEY);
    if (hPublicKey == CK_INVALID_HANDLE) {
        result.errorMessage = "Public key '" + keyLabel + "' not found in slot " + std::to_string(slotId);
        pFunctionList->C_CloseSession(hSession);
        pFunctionList->C_Finalize(nullptr);
        return result;
    }

    std::cout << "Found key pair '" << keyLabel << "'" << std::endl;

    // Get key attributes
    if (!getKeyAttributes(pFunctionList, hSession, hPrivateKey, &result.keyType, &result.keySize)) {
        result.errorMessage = "Failed to get key attributes";
        pFunctionList->C_CloseSession(hSession);
        pFunctionList->C_Finalize(nullptr);
        return result;
    }

    std::cout << "Key type: " << getKeyTypeName(result.keyType) << "-" << result.keySize << std::endl;

    // Get signing mechanism - try hash-based first, then fallback to plain
    CK_MECHANISM_TYPE mechType = getSigningMechanism(result.keyType, true);
    CK_MECHANISM mechanism = {mechType, nullptr, 0};
    
    // Test if mechanism is supported
    CK_SESSION_HANDLE hTestSession;
    CK_RV testRv = pFunctionList->C_OpenSession(slotId, CKF_SERIAL_SESSION, nullptr, nullptr, &hTestSession);
    if (testRv != CKR_OK) {
        result.errorMessage = "Failed to open test session. Error: " + rvToHexString(testRv);
        pFunctionList->C_CloseSession(hSession);
        pFunctionList->C_Finalize(nullptr);
        return result;
    }
    
    // Test signing mechanism
    testRv = pFunctionList->C_SignInit(hTestSession, &mechanism, hPrivateKey);
    if (testRv != CKR_OK) {
        std::cout << "Hash-based mechanism not supported, trying plain mechanism..." << std::endl;
        // Try plain mechanism
        mechType = getSigningMechanism(result.keyType, false);
        mechanism.mechanism = mechType;
        testRv = pFunctionList->C_SignInit(hTestSession, &mechanism, hPrivateKey);
        if (testRv != CKR_OK) {
            result.errorMessage = "Neither hash-based nor plain mechanism supported. Hash error: " + 
                                  rvToHexString(testRv) + ", Plain error: " + rvToHexString(testRv);
            pFunctionList->C_CloseSession(hTestSession);
            pFunctionList->C_CloseSession(hSession);
            pFunctionList->C_Finalize(nullptr);
            return result;
        }
    }
    pFunctionList->C_CloseSession(hTestSession);
    
    std::string mechName;
    if (mechType == CKM_DSA_SHA256) mechName = "DSA-SHA256";
    else if (mechType == CKM_DSA) mechName = "DSA";
    else if (mechType == CKM_SHA256_RSA_PKCS) mechName = "SHA256-RSA-PKCS";
    else if (mechType == CKM_RSA_PKCS) mechName = "RSA-PKCS";
    else if (mechType == CKM_ECDSA_SHA256) mechName = "ECDSA-SHA256";
    else if (mechType == CKM_ECDSA) mechName = "ECDSA";
    else mechName = "Unknown";
    
    std::cout << " Using mechanism: " << mechName << std::endl;

    // Prepare test data
    std::vector<CK_BYTE> testData;
    std::vector<CK_BYTE> rawData(dataSize);
    for (size_t i = 0; i < dataSize; i++) {
        rawData[i] = static_cast<CK_BYTE>(i % 256);
    }
    
    // For plain mechanisms (non-hash), we need to provide pre-hashed data
    if (mechType == CKM_DSA || mechType == CKM_ECDSA || mechType == CKM_RSA_PKCS) {
        // For DSA, we need exactly 20 bytes (SHA-1) or use first 20 bytes
        if (mechType == CKM_DSA) {
            testData.resize(20);
            for (int i = 0; i < 20; i++) {
                testData[i] = rawData[i % dataSize];
            }
            std::cout << "Using 20-byte hash for plain DSA mechanism" << std::endl;
        } else {
            // For other plain mechanisms, use the raw data (but may need hashing)
            testData = rawData;
        }
    } else {
        // For hash-based mechanisms, use the raw data
        testData = rawData;
    }

    std::cout << "Starting " << rounds << " rounds of sign/verify testing..." << std::endl;
    std::cout << "Test data size: " << dataSize << " bytes" << std::endl;

    double totalSignTime = 0.0;
    double totalVerifyTime = 0.0;
    int successfulRounds = 0;

    for (int round = 0; round < rounds; round++) {
        // Signing operation
        auto signStart = std::chrono::high_resolution_clock::now();
        
        rv = pFunctionList->C_SignInit(hSession, &mechanism, hPrivateKey);
        if (rv != CKR_OK) {
            result.errorMessage = "Failed to initialize signing in round " + std::to_string(round + 1) + 
                                  ". Error: " + rvToHexString(rv);
            break;
        }

        // Get signature length
        CK_ULONG signatureLen = 0;
        rv = pFunctionList->C_Sign(hSession, testData.data(), static_cast<CK_ULONG>(testData.size()), 
                                  nullptr, &signatureLen);
        if (rv != CKR_OK) {
            result.errorMessage = "Failed to get signature length in round " + std::to_string(round + 1) + 
                                  ". Error: " + rvToHexString(rv);
            break;
        }

        // Perform actual signing
        std::vector<CK_BYTE> signature(signatureLen);
        rv = pFunctionList->C_Sign(hSession, testData.data(), static_cast<CK_ULONG>(testData.size()), 
                                  signature.data(), &signatureLen);
        
        auto signEnd = std::chrono::high_resolution_clock::now();
        
        if (rv != CKR_OK) {
            result.errorMessage = "Failed to sign data in round " + std::to_string(round + 1) + 
                                  ". Error: " + rvToHexString(rv);
            break;
        }

        // Verification operation
        auto verifyStart = std::chrono::high_resolution_clock::now();
        
        rv = pFunctionList->C_VerifyInit(hSession, &mechanism, hPublicKey);
        if (rv != CKR_OK) {
            result.errorMessage = "Failed to initialize verification in round " + std::to_string(round + 1) + 
                                  ". Error: " + rvToHexString(rv);
            break;
        }

        rv = pFunctionList->C_Verify(hSession, testData.data(), static_cast<CK_ULONG>(testData.size()), 
                                      signature.data(), signatureLen);
        
        auto verifyEnd = std::chrono::high_resolution_clock::now();
        
        if (rv != CKR_OK) {
            result.errorMessage = "Failed to verify signature in round " + std::to_string(round + 1) + 
                                  ". Error: " + rvToHexString(rv);
            break;
        }

        // Calculate timing
        double signTime = std::chrono::duration<double, std::milli>(signEnd - signStart).count();
        double verifyTime = std::chrono::duration<double, std::milli>(verifyEnd - verifyStart).count();
        
        totalSignTime += signTime;
        totalVerifyTime += verifyTime;
        successfulRounds++;

        // Store signature size from first round
        if (round == 0) {
            result.signatureSize = signatureLen;
        }

        // Progress indicator every 10 rounds
        if ((round + 1) % 10 == 0) {
            std::cout << "Completed " << (round + 1) << "/" << rounds << " rounds..." << std::endl;
        }
    }

    // Clean up
    pFunctionList->C_CloseSession(hSession);
    pFunctionList->C_Finalize(nullptr);

    if (successfulRounds > 0) {
        result.success = true;
        result.avgSignTime = totalSignTime / successfulRounds;
        result.avgVerifyTime = totalVerifyTime / successfulRounds;
        
        std::cout << "\nBenchmark completed successfully!" << std::endl;
        std::cout << "Successful rounds: " << successfulRounds << "/" << rounds << std::endl;
    } else {
        result.success = false;
        if (result.errorMessage.empty()) {
            result.errorMessage = "No successful rounds completed";
        }
    }

    return result;
}

// Function to print the final benchmark results
void printBenchmarkResults(const BenchmarkResult& result) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "BENCHMARK RESULTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    
    std::cout << "Key Label: " << result.keyLabel << std::endl;
    std::cout << "Slot ID: " << result.slotId << std::endl;
    
    if (!result.success) {
        std::cout << "Status: FAILED" << std::endl;
        std::cout << "Error: " << result.errorMessage << std::endl;
        return;
    }

    std::cout << "Status: SUCCESS" << std::endl;
    std::cout << "Key Type: " << getKeyTypeName(result.keyType) << " " << result.keySize << "bit" <<std::endl;
    std::cout << "Data Size: " << result.dataSize << " bytes" << std::endl;
    std::cout << "Signature Size: " << result.signatureSize << " bytes" << std::endl;
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Average Sign Time: " << result.avgSignTime << " ms" << std::endl;
    std::cout << "Average Verify Time: " << result.avgVerifyTime << " ms" << std::endl;
    std::cout << "Total Time per Round: " << (result.avgSignTime + result.avgVerifyTime) << " ms" << std::endl;
}

// Function to print usage instructions
void printUsage() {
    std::cout << "Usage: key_lookup_benchmark <slot_id> <key_label> [data_size] [rounds]" << std::endl;
    std::cout << std::endl;
    std::cout << "Parameters:" << std::endl;
    std::cout << "  slot_id    : PKCS#11 slot ID (e.g., 0, 1, 2...)" << std::endl;
    std::cout << "  key_label  : Label of the key to find (e.g., \"3072dsa\")" << std::endl;
    std::cout << "  data_size  : Size of test data in bytes (default: 1024)" << std::endl;
    std::cout << "  rounds     : Number of sign/verify rounds (default: 100)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  key_lookup_benchmark 0 \"3072dsa\"" << std::endl;
    std::cout << "  key_lookup_benchmark 1 \"rsa2048\" 2048 50" << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "Benchmark Tool" << std::endl;
    std::cout << "=========================" << std::endl;

    if (argc < 3 || argc > 5) {
        printUsage();
        return 1;
    }

    try {
        CK_SLOT_ID slotId = static_cast<CK_SLOT_ID>(std::stoul(argv[1]));
        std::string keyLabel = argv[2];
        size_t dataSize = (argc >= 4) ? std::stoul(argv[3]) : 1024;
        int rounds = (argc >= 5) ? std::stoi(argv[4]) : 100;

        std::cout << "Configuration:" << std::endl;
        std::cout << "  Slot ID: " << slotId << std::endl;
        std::cout << "  Key Label: '" << keyLabel << "'" << std::endl;
        std::cout << "  Data Size: " << dataSize << " bytes" << std::endl;
        std::cout << "  Rounds: " << rounds << std::endl;
        std::cout << std::endl;

        BenchmarkResult result = performKeyLookupBenchmark(slotId, keyLabel, dataSize, rounds);
        printBenchmarkResults(result);

        return result.success ? 0 : 1;

    } catch (const std::exception& e) {
        std::cerr << "Error parsing arguments: " << e.what() << std::endl;
        printUsage();
        return 1;
    }
}
