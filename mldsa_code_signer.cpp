/*
 * ML-DSA DLL Code Signing with Embedded Signatures
 * 
 * This application demonstrates post-quantum code signing using ML-DSA:
 * - Signs existing DLL files with ML-DSA keys stored in HSM
 * - Computes SHA-256 hash of the DLL content
 * - Signs the hash using existing ML-DSA keys (looked up by name)
 * - Embeds the signed hash into the DLL file
 * - Validates embedded signatures in signed DLL files
 * 
 * USAGE:
 *   Sign a DLL:    mldsa_code_signer.exe <file.dll> <key_name>
 *   Verify a DLL:  mldsa_code_signer.exe <signed_file.dll> --verify
 * 
 * WORKFLOW (Signing):
 * 1. Look up existing ML-DSA key pair by name in HSM
 * 2. Load existing DLL file
 * 3. Hash the DLL content (SHA-256)
 * 4. Sign the hash with ML-DSA private key
 * 5. Embed signature into DLL file
 * 
 * WORKFLOW (Verification):
 * 1. Load signed DLL file
 * 2. Extract embedded signature and public key
 * 3. Verify embedded signature with ML-DSA public key
 * 
 * PURPOSE:
 * Demonstrates post-quantum code signing in environments where:
 * - Vendor compatibility is limited
 * - Traditional code signing infrastructure doesn't support PQ algorithms
 * - Custom signature embedding/verification is needed
 * - Existing ML-DSA keys need to be reused
 * 
 * IMPORTANT: nCipher nShield Usage Requirements
 * ============================================
 * 
 * For softcard slots, you must preload the softcard before running:
 * 
 *     preload -s <SoftcardName> .\mldsa_dll_signer.exe <file.dll> <key_name>
 * 
 * Example:
 *     preload -s TestSoftcard .\mldsa_dll_signer.exe mydll.dll "ML-DSA-65-Key"
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <fstream>
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

// PKCS#11 function list
CK_FUNCTION_LIST_PTR pFunctionList = NULL;

// Helper to get hex string from CK_RV
std::string rvToHexString(CK_RV rv) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << rv;
    return ss.str();
}

// Function to find a key by label in a specific slot
CK_OBJECT_HANDLE findKeyByLabel(CK_SESSION_HANDLE hSession, const std::string& keyLabel, CK_OBJECT_CLASS keyClass) {
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

// Function to get ML-DSA parameter set from key
CK_ML_DSA_PARAMETER_SET_TYPE getMLDSAParameterSet(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
    CK_ML_DSA_PARAMETER_SET_TYPE paramSet = 0;
    CK_ATTRIBUTE paramSetAttr = {CKA_PARAMETER_SET, &paramSet, sizeof(paramSet)};
    
    CK_RV rv = pFunctionList->C_GetAttributeValue(hSession, hKey, &paramSetAttr, 1);
    if (rv != CKR_OK) {
        std::cerr << "Failed to get ML-DSA parameter set. Error: " << rvToHexString(rv) << std::endl;
        return 0;
    }
    
    return paramSet;
}

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

// Signature embedding structure
struct EmbeddedSignature {
    char magic[16];           // "MLDSA_SIGNATURE\0"
    uint32_t version;         // Version number
    uint32_t parameterSet;    // ML-DSA parameter set used
    uint32_t hashSize;        // Size of hash (32 for SHA-256)
    uint32_t signatureSize;   // Size of signature
    uint32_t publicKeySize;   // Size of public key
    // Followed by: hash + signature + public key
};

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
    std::cout << "ML-DSA DLL Code Signing Tool" << std::endl;
    std::cout << "===============================================" << std::endl;
    std::cout << "Post-Quantum Code Signing with Embedded Signatures" << std::endl;
    std::cout << "Process: DLL --> SHA-256 Hash -->  ML-DSA Key Signs --> Embed Data -->  Verify Signature" << std::endl;
    std::cout << "Purpose: Demonstrate PQ signatures in limited compatibility environments" << std::endl;
    std::cout << "===============================================\n" << std::endl;
    
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

std::vector<CK_SLOT_ID> getAvailableSlots() {
    std::cout << "\nGetting available HSM slots..." << std::endl;
    
    std::vector<CK_SLOT_ID> compatibleSlots;
    
    // Get number of slots
    CK_ULONG slotCount = 0;
    CK_RV rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL, &slotCount);
    if (rv != CKR_OK || slotCount == 0) {
        std::cerr << "No slots with tokens found." << std::endl;
        return compatibleSlots;
    }
    
    // Get slot IDs
    std::vector<CK_SLOT_ID> slotList(slotCount);
    rv = pFunctionList->C_GetSlotList(CK_TRUE, slotList.data(), &slotCount);
    if (rv != CKR_OK) {
        std::cerr << "Error: C_GetSlotList failed" << std::endl;
        return compatibleSlots;
    }
    
    std::cout << "Found " << slotCount << " slot(s) with tokens:" << std::endl;
    
    // Check each slot for ML-DSA and SHA-256 support
    for (CK_ULONG i = 0; i < slotCount; i++) {
        CK_SLOT_INFO slotInfo;
        rv = pFunctionList->C_GetSlotInfo(slotList[i], &slotInfo);
        std::string slotDesc = "Unknown";
        if (rv == CKR_OK) {
            slotDesc = std::string(reinterpret_cast<char*>(slotInfo.slotDescription), 64);
            slotDesc.erase(slotDesc.find_last_not_of(" ") + 1);
        }
        
        CK_ULONG mechanismCount = 0;
        rv = pFunctionList->C_GetMechanismList(slotList[i], NULL, &mechanismCount);
        if (rv == CKR_OK && mechanismCount > 0) {
            std::vector<CK_MECHANISM_TYPE> mechanisms(mechanismCount);
            rv = pFunctionList->C_GetMechanismList(slotList[i], mechanisms.data(), &mechanismCount);
            if (rv == CKR_OK) {
                bool supportsMLDSA = false;
                bool supportsSHA256 = false;
                
                for (CK_ULONG j = 0; j < mechanismCount; j++) {
                    if (mechanisms[j] == CKM_ML_DSA || mechanisms[j] == CKM_ML_DSA_KEY_PAIR_GEN) {
                        supportsMLDSA = true;
                    }
                    if (mechanisms[j] == CKM_SHA256) {
                        supportsSHA256 = true;
                    }
                }
                
                std::cout << "  Slot " << slotList[i] << ": " << slotDesc 
                          << " (ML-DSA: " << (supportsMLDSA ? "Yes" : "No")
                          << ", SHA-256: " << (supportsSHA256 ? "Yes" : "No") << ")" << std::endl;
                
                if (supportsMLDSA && supportsSHA256) {
                    compatibleSlots.push_back(slotList[i]);
                }
            }
        }
    }
    
    return compatibleSlots;
}

std::vector<CK_BYTE> computeSHA256Hash(CK_SESSION_HANDLE hSession, const std::vector<CK_BYTE>& data) {
    CK_MECHANISM hashMechanism = {CKM_SHA256, NULL, 0};
    std::vector<CK_BYTE> hash(32); // SHA-256 produces 32-byte hash
    CK_ULONG hashLen = 32;
    
    CK_RV rv = pFunctionList->C_DigestInit(hSession, &hashMechanism);
    if (rv != CKR_OK) {
        throw std::runtime_error("SHA-256 digest init failed");
    }
    
    rv = pFunctionList->C_Digest(hSession, const_cast<CK_BYTE*>(data.data()), 
                                static_cast<CK_ULONG>(data.size()), hash.data(), &hashLen);
    if (rv != CKR_OK) {
        throw std::runtime_error("SHA-256 digest failed");
    }
    
    return hash;
}

struct KeyPairInfo {
    CK_SLOT_ID slotId;
    CK_OBJECT_HANDLE hPublicKey;
    CK_OBJECT_HANDLE hPrivateKey;
    CK_ML_DSA_PARAMETER_SET_TYPE parameterSet;
    std::string slotDescription;
    bool found;
};

KeyPairInfo findMLDSAKeyPair(const std::vector<CK_SLOT_ID>& slots, const std::string& keyLabel) {
    std::cout << "\nSearching for ML-DSA key pair '" << keyLabel << "'..." << std::endl;
    
    KeyPairInfo keyInfo;
    keyInfo.found = false;
    keyInfo.hPublicKey = CK_INVALID_HANDLE;
    keyInfo.hPrivateKey = CK_INVALID_HANDLE;
    keyInfo.parameterSet = 0;
    
    for (CK_SLOT_ID slotId : slots) {
        CK_SESSION_HANDLE hSession;
        CK_RV rv = pFunctionList->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
        if (rv != CKR_OK) {
            std::cout << "  Slot " << slotId << ": Failed to open session" << std::endl;
            continue;
        }
        
        // Try to login for card slots
        CK_SLOT_INFO slotInfo;
        rv = pFunctionList->C_GetSlotInfo(slotId, &slotInfo);
        std::string slotDesc = "Unknown";
        if (rv == CKR_OK) {
            slotDesc = std::string(reinterpret_cast<char*>(slotInfo.slotDescription), 64);
            slotDesc.erase(slotDesc.find_last_not_of(" ") + 1);
        }
        
        // Check if this looks like a card slot
        bool isCardSlot = (slotDesc.find("card") != std::string::npos) ||
                          (slotDesc.find("Card") != std::string::npos);
        
        if (isCardSlot) {
            rv = pFunctionList->C_Login(hSession, CKU_USER, NULL, 0);
            if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
                std::cout << "  Slot " << slotId << " (" << slotDesc << "): Login failed, continuing..." << std::endl;
            }
        }
        
        // Look for private key
        CK_OBJECT_HANDLE hPrivateKey = findKeyByLabel(hSession, keyLabel, CKO_PRIVATE_KEY);
        if (hPrivateKey == CK_INVALID_HANDLE) {
            std::cout << "  Slot " << slotId << " (" << slotDesc << "): Private key not found" << std::endl;
            pFunctionList->C_CloseSession(hSession);
            continue;
        }
        
        // Look for public key
        CK_OBJECT_HANDLE hPublicKey = findKeyByLabel(hSession, keyLabel, CKO_PUBLIC_KEY);
        if (hPublicKey == CK_INVALID_HANDLE) {
            std::cout << "  Slot " << slotId << " (" << slotDesc << "): Public key not found" << std::endl;
            pFunctionList->C_CloseSession(hSession);
            continue;
        }
        
        // Verify it's an ML-DSA key and get parameter set
        CK_KEY_TYPE keyType;
        CK_ATTRIBUTE keyTypeAttr = {CKA_KEY_TYPE, &keyType, sizeof(keyType)};
        rv = pFunctionList->C_GetAttributeValue(hSession, hPrivateKey, &keyTypeAttr, 1);
        if (rv != CKR_OK || keyType != CKK_ML_DSA) {
            std::cout << "  Slot " << slotId << " (" << slotDesc << "): Not an ML-DSA key" << std::endl;
            pFunctionList->C_CloseSession(hSession);
            continue;
        }
        
        CK_ML_DSA_PARAMETER_SET_TYPE paramSet = getMLDSAParameterSet(hSession, hPrivateKey);
        if (paramSet == 0) {
            std::cout << "  Slot " << slotId << " (" << slotDesc << "): Could not get ML-DSA parameter set" << std::endl;
            pFunctionList->C_CloseSession(hSession);
            continue;
        }
        
        // Found the key pair!
        keyInfo.found = true;
        keyInfo.slotId = slotId;
        keyInfo.hPublicKey = hPublicKey;
        keyInfo.hPrivateKey = hPrivateKey;
        keyInfo.parameterSet = paramSet;
        keyInfo.slotDescription = slotDesc;
        
        std::string paramSetName;
        if (paramSet == CKP_ML_DSA_44) paramSetName = "ML-DSA-44";
        else if (paramSet == CKP_ML_DSA_65) paramSetName = "ML-DSA-65";
        else if (paramSet == CKP_ML_DSA_87) paramSetName = "ML-DSA-87";
        else paramSetName = "Unknown";
        
        std::cout << "  Found ML-DSA key pair in slot " << slotId << " (" << slotDesc << ")" << std::endl;
        std::cout << "   Parameter set: " << paramSetName << std::endl;
        
        pFunctionList->C_CloseSession(hSession);
        break;
    }
    
    if (!keyInfo.found) {
        std::cerr << "ML-DSA key pair '" << keyLabel << "' not found in any slot" << std::endl;
    }
    
    return keyInfo;
}

// Helper function to find ML-DSA key pair by name using existing session
bool findMLDSAKeyPairByName(CK_SESSION_HANDLE hSession, const std::string& keyName, 
                           CK_OBJECT_HANDLE& hPublicKey, CK_OBJECT_HANDLE& hPrivateKey) {
    // Get all slots to search
    auto slots = getAvailableSlots();
    
    // Use existing findMLDSAKeyPair function
    KeyPairInfo keyInfo = findMLDSAKeyPair(slots, keyName);
    
    if (keyInfo.found) {
        hPublicKey = keyInfo.hPublicKey;
        hPrivateKey = keyInfo.hPrivateKey;
        return true;
    }
    
    return false;
}

std::vector<CK_BYTE> readFileContent(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file for reading");
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<CK_BYTE> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Could not read file content");
    }
    
    return buffer;
}

MLDSAParameterSet getMLDSAParamSetInfo(CK_ML_DSA_PARAMETER_SET_TYPE paramSet) {
    auto paramSets = getMLDSAParameterSets();
    for (const auto& ps : paramSets) {
        if (ps.parameterSet == paramSet) {
            return ps;
        }
    }
    // Default fallback
    return paramSets[1]; // ML-DSA-65
}

void printUsage() {
    std::cout << "ML-DSA DLL Code Signing Tool" << std::endl;
    std::cout << "=============================" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  Sign a DLL:    mldsa_dll_signer.exe <file.dll> <key_name>" << std::endl;
    std::cout << "  Verify a DLL:  mldsa_dll_signer.exe <signed_file.dll> <key_name> --verify" << std::endl;
    std::cout << std::endl;
    std::cout << "Parameters:" << std::endl;
    std::cout << "  file.dll       : Path to the DLL file to sign or verify" << std::endl;
    std::cout << "  key_name       : Name/label of the ML-DSA key in the HSM" << std::endl;
    std::cout << "  --verify       : Verify an already signed DLL file" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  mldsa_dll_signer.exe mydll.dll \"ML-DSA-65-Key\"" << std::endl;
    std::cout << "  mldsa_dll_signer.exe signed_mydll.dll \"ML-DSA-65-Key\" --verify" << std::endl;
    std::cout << std::endl;
    std::cout << "Note: For softcard slots, preload the softcard:" << std::endl;
    std::cout << "  preload -s SoftcardName mldsa_dll_signer.exe mydll.dll \"KeyName\"" << std::endl;
}

std::vector<CK_BYTE> getPublicKeyData(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey) {
    // Get the public key value
    CK_ATTRIBUTE template1[] = {{CKA_VALUE, NULL, 0}};
    CK_RV rv = pFunctionList->C_GetAttributeValue(hSession, hPublicKey, template1, 1);
    if (rv != CKR_OK) {
        throw std::runtime_error("Could not get public key size");
    }
    
    std::vector<CK_BYTE> publicKeyData(template1[0].ulValueLen);
    template1[0].pValue = publicKeyData.data();
    
    rv = pFunctionList->C_GetAttributeValue(hSession, hPublicKey, template1, 1);
    if (rv != CKR_OK) {
        throw std::runtime_error("Could not get public key data");
    }
    
    return publicKeyData;
}

std::vector<CK_BYTE> signHash(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPrivateKey, 
                             const std::vector<CK_BYTE>& hash) {
    std::cout << "\nSigning hash with ML-DSA private key..." << std::endl;
    
    CK_MECHANISM signMechanism = {CKM_ML_DSA, NULL, 0};
    
    CK_RV rv = pFunctionList->C_SignInit(hSession, &signMechanism, hPrivateKey);
    if (rv != CKR_OK) {
        throw std::runtime_error("Sign init failed");
    }
    
    // Get signature size
    CK_ULONG signatureSize = 0;
    rv = pFunctionList->C_Sign(hSession, const_cast<CK_BYTE*>(hash.data()), 
                              static_cast<CK_ULONG>(hash.size()), NULL, &signatureSize);
    if (rv != CKR_OK) {
        throw std::runtime_error("Could not get signature size");
    }
    
    std::vector<CK_BYTE> signature(signatureSize);
    auto signStart = std::chrono::high_resolution_clock::now();
    rv = pFunctionList->C_Sign(hSession, const_cast<CK_BYTE*>(hash.data()), 
                              static_cast<CK_ULONG>(hash.size()), signature.data(), &signatureSize);
    auto signEnd = std::chrono::high_resolution_clock::now();
    
    if (rv != CKR_OK) {
        throw std::runtime_error("Signing failed");
    }
    
    double signTimeMs = std::chrono::duration<double, std::milli>(signEnd - signStart).count();
    std::cout << "Hash signed successfully in " << std::fixed << std::setprecision(3) 
              << signTimeMs << " ms" << std::endl;
    std::cout << "Signature size: " << signatureSize << " bytes" << std::endl;
    
    signature.resize(signatureSize);
    return signature;
}

bool embedSignatureInDLL(const std::string& filename, const std::vector<CK_BYTE>& hash,
                        const std::vector<CK_BYTE>& signature, const std::vector<CK_BYTE>& publicKey,
                        const MLDSAParameterSet& paramSet) {
    std::cout << "\nEmbedding signature into DLL file..." << std::endl;
    
    // Read current file content
    auto dllContent = readFileContent(filename);
    
    // Create embedded signature structure
    EmbeddedSignature embSig;
    strcpy(embSig.magic, "MLDSA_SIGNATURE");
    embSig.version = 1;
    embSig.parameterSet = static_cast<uint32_t>(paramSet.parameterSet);
    embSig.hashSize = static_cast<uint32_t>(hash.size());
    embSig.signatureSize = static_cast<uint32_t>(signature.size());
    embSig.publicKeySize = static_cast<uint32_t>(publicKey.size());
    
    // Open file for appending
    std::ofstream file(filename, std::ios::binary | std::ios::app);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open DLL file for embedding" << std::endl;
        return false;
    }
    
    // Write signature structure
    file.write(reinterpret_cast<const char*>(&embSig), sizeof(embSig));
    
    // Write hash, signature, and public key
    file.write(reinterpret_cast<const char*>(hash.data()), hash.size());
    file.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    file.write(reinterpret_cast<const char*>(publicKey.data()), publicKey.size());
    
    file.close();
    
    std::cout << "Signature embedded successfully!" << std::endl;
    std::cout << "  Embedded signature size: " << sizeof(embSig) + hash.size() + signature.size() + publicKey.size() << " bytes" << std::endl;
    // Get file size for reporting
    std::ifstream sizeFile(filename, std::ifstream::ate | std::ifstream::binary);
    size_t fileSize = 0;
    if (sizeFile.is_open()) {
        fileSize = sizeFile.tellg();
        sizeFile.close();
    }
    std::cout << "  Total DLL size: " << fileSize << " bytes" << std::endl;
    
    return true;
}

bool verifyEmbeddedSignature(CK_SESSION_HANDLE hSession, const std::string& filename, 
                           const std::string& keyName) {
    std::cout << "\nVerifying embedded signature..." << std::endl;
    
    // Read file content
    auto fileContent = readFileContent(filename);
    
    // Look for signature magic at the end of file
    if (fileContent.size() < sizeof(EmbeddedSignature)) {
        std::cerr << "Error: File too small to contain embedded signature" << std::endl;
        return false;
    }
    
    // Find the signature structure (search backwards from end)
    bool found = false;
    size_t sigPos = 0;
    const char* magic = "MLDSA_SIGNATURE";
    
    for (size_t i = fileContent.size() - sizeof(EmbeddedSignature); i > 0; --i) {
        if (memcmp(&fileContent[i], magic, strlen(magic)) == 0) {
            sigPos = i;
            found = true;
            break;
        }
    }
    
    if (!found) {
        std::cerr << "Error: No embedded signature found in DLL" << std::endl;
        return false;
    }
    
    // Extract signature structure
    EmbeddedSignature* embSig = reinterpret_cast<EmbeddedSignature*>(&fileContent[sigPos]);
    
    std::cout << "Found embedded signature:" << std::endl;
    std::cout << "  Version: " << embSig->version << std::endl;
    std::cout << "  Parameter set: " << embSig->parameterSet << std::endl;
    std::cout << "  Hash size: " << embSig->hashSize << " bytes" << std::endl;
    std::cout << "  Signature size: " << embSig->signatureSize << " bytes" << std::endl;
    std::cout << "  Public key size: " << embSig->publicKeySize << " bytes" << std::endl;
    
    // Get parameter set info from embedded signature
    MLDSAParameterSet actualParamSet = getMLDSAParamSetInfo(static_cast<CK_ML_DSA_PARAMETER_SET_TYPE>(embSig->parameterSet));
    std::cout << "  Algorithm: " << actualParamSet.name << " (" << actualParamSet.description << ")" << std::endl;
    
    // Extract components
    size_t dataPos = sigPos + sizeof(EmbeddedSignature);
    std::vector<CK_BYTE> embeddedHash(embSig->hashSize);
    std::vector<CK_BYTE> embeddedSignature(embSig->signatureSize);
    std::vector<CK_BYTE> embeddedPublicKey(embSig->publicKeySize);
    
    memcpy(embeddedHash.data(), &fileContent[dataPos], embSig->hashSize);
    dataPos += embSig->hashSize;
    
    memcpy(embeddedSignature.data(), &fileContent[dataPos], embSig->signatureSize);
    dataPos += embSig->signatureSize;
    
    memcpy(embeddedPublicKey.data(), &fileContent[dataPos], embSig->publicKeySize);
    
    // Compute hash of original DLL content (without embedded signature)
    std::vector<CK_BYTE> originalContent(fileContent.begin(), fileContent.begin() + sigPos);
    auto computedHash = computeSHA256Hash(hSession, originalContent);
    
    // Verify hash matches
    if (embeddedHash != computedHash) {
        std::cerr << "Error: Hash mismatch - DLL content has been modified!" << std::endl;
        std::cout << "  Embedded hash: " << bytesToHex(embeddedHash, 16) << std::endl;
        std::cout << "  Computed hash: " << bytesToHex(computedHash, 16) << std::endl;
        return false;
    }
    
    std::cout << "Hash verification: PASSED" << std::endl;
    std::cout << "  Hash matches: " << bytesToHex(computedHash, 16) << std::endl;
    
    // Look up the public key from HSM using key name
    std::cout << "\nLooking up public key '" << keyName << "' from HSM..." << std::endl;
    
    CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPrivateKey = CK_INVALID_HANDLE;
    
    if (!findMLDSAKeyPairByName(hSession, keyName, hPublicKey, hPrivateKey)) {
        std::cerr << "Error: Could not find ML-DSA key pair with name '" << keyName << "'" << std::endl;
        return false;
    }
    
    std::cout << "Found public key in HSM" << std::endl;
    
    // Get the HSM public key data to compare with embedded key (optional security check)
    auto hsmPublicKey = getPublicKeyData(hSession, hPublicKey);
    
    if (hsmPublicKey != embeddedPublicKey) {
        std::cerr << "Warning: Embedded public key differs from HSM public key!" << std::endl;
        std::cout << "  This could indicate key mismatch or tampering." << std::endl;
        std::cout << "  HSM public key:      " << bytesToHex(hsmPublicKey, 16) << std::endl;
        std::cout << "  Embedded public key: " << bytesToHex(embeddedPublicKey, 16) << std::endl;
        std::cout << "  Continuing verification with HSM public key..." << std::endl;
    } else {
        std::cout << "Public key verification: PASSED" << std::endl;
        std::cout << "  Embedded public key matches HSM public key" << std::endl;
    }
    
    // Verify signature using HSM public key
    CK_MECHANISM verifyMechanism = {CKM_ML_DSA, NULL, 0};
    
    CK_RV rv = pFunctionList->C_VerifyInit(hSession, &verifyMechanism, hPublicKey);
    if (rv != CKR_OK) {
        std::cerr << "Error: Verify init failed (error 0x" << std::hex << rv << std::dec << ")" << std::endl;
        return false;
    }
    
    auto verifyStart = std::chrono::high_resolution_clock::now();
    rv = pFunctionList->C_Verify(hSession, computedHash.data(), static_cast<CK_ULONG>(computedHash.size()),
                                embeddedSignature.data(), static_cast<CK_ULONG>(embeddedSignature.size()));
    auto verifyEnd = std::chrono::high_resolution_clock::now();
    
    if (rv != CKR_OK) {
        std::cerr << "Error: Signature verification FAILED (error 0x" << std::hex << rv << std::dec << ")" << std::endl;
        return false;
    }
    
    double verifyTimeMs = std::chrono::duration<double, std::milli>(verifyEnd - verifyStart).count();
    std::cout << "Signature verification: PASSED" << std::endl;
    std::cout << "  Verification time: " << std::fixed << std::setprecision(3) << verifyTimeMs << " ms" << std::endl;
    std::cout << "  Original file size: " << originalContent.size() << " bytes" << std::endl;
    std::cout << "  Used HSM key: " << keyName << std::endl;
    
    return true;
}

int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc < 3 || argc > 4) {
        printUsage();
        return 1;
    }
    
    std::string dllFilename = argv[1];
    std::string keyName = argv[2];
    bool verifyMode = false;
    
    if (argc == 4) {
        std::string thirdArg = argv[3];
        if (thirdArg == "--verify") {
            verifyMode = true;
        } else {
            std::cerr << "Error: Unknown option '" << thirdArg << "'" << std::endl;
            printUsage();
            return 1;
        }
    }
    
    // Check if file exists
    std::ifstream fileCheck(dllFilename);
    if (!fileCheck.good()) {
        std::cerr << "Error: File '" << dllFilename << "' does not exist." << std::endl;
        return 1;
    }
    
    if (!initializePKCS11()) {
        std::cerr << "Failed to initialize PKCS#11" << std::endl;
        return 1;
    }
    
    if (verifyMode) {
        // Verification mode
        std::cout << "ML-DSA DLL Signature Verification" << std::endl;
        std::cout << "==================================" << std::endl;
        std::cout << "File: " << dllFilename << std::endl;
        
        // Open a session on any available slot for verification
        auto slots = getAvailableSlots();
        if (slots.empty()) {
            std::cerr << "No compatible HSM slots found" << std::endl;
            return 1;
        }
        
        CK_SESSION_HANDLE hSession;
        CK_RV rv = pFunctionList->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
        if (rv != CKR_OK) {
            std::cerr << "Error: Could not open session for verification" << std::endl;
            return 1;
        }
        
        try {
            // Verify the embedded signature using the specified key
            if (!verifyEmbeddedSignature(hSession, dllFilename, keyName)) {
                std::cerr << "Signature verification failed!" << std::endl;
                pFunctionList->C_CloseSession(hSession);
                return 1;
            }
            
            std::cout << "\nDLL signature verification: PASSED" << std::endl;
            std::cout << "File integrity: VERIFIED" << std::endl;
            
        } catch (const std::exception& e) {
            std::cerr << "\nError during verification: " << e.what() << std::endl;
            pFunctionList->C_CloseSession(hSession);
            return 1;
        }
        
        pFunctionList->C_CloseSession(hSession);
        
    } else {
        // Signing mode
        std::cout << "ML-DSA DLL Code Signing Tool" << std::endl;
        std::cout << "============================" << std::endl;
        std::cout << "File: " << dllFilename << std::endl;
        std::cout << "Key: " << keyName << std::endl;
        
        // Get available slots
        auto slots = getAvailableSlots();
        if (slots.empty()) {
            std::cerr << "No compatible HSM slots found" << std::endl;
            return 1;
        }
        
        // Find the ML-DSA key pair
        KeyPairInfo keyInfo = findMLDSAKeyPair(slots, keyName);
        if (!keyInfo.found) {
            return 1;
        }
        
        // Open session on the slot containing the key
        CK_SESSION_HANDLE hSession;
        CK_RV rv = pFunctionList->C_OpenSession(keyInfo.slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
        if (rv != CKR_OK) {
            std::cerr << "Error: Could not open session on slot " << keyInfo.slotId << std::endl;
            return 1;
        }
        
        // Login if needed (for card slots)
        bool isCardSlot = (keyInfo.slotDescription.find("card") != std::string::npos) ||
                          (keyInfo.slotDescription.find("Card") != std::string::npos);
        
        if (isCardSlot) {
            rv = pFunctionList->C_Login(hSession, CKU_USER, NULL, 0);
            if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
                std::cout << "Login to card slot may be required for signing operations" << std::endl;
            }
        }
        
        try {
            // Get the parameter set info
            MLDSAParameterSet paramSetInfo = getMLDSAParamSetInfo(keyInfo.parameterSet);
            
            std::cout << "\nML-DSA Parameter Set: " << paramSetInfo.name 
                      << " (" << paramSetInfo.description << ")" << std::endl;
            std::cout << "NIST Security Level: " << paramSetInfo.nistLevel << std::endl;
            std::cout << "Security Equivalent: " << paramSetInfo.securityEquivalent << std::endl;
            
            // Read and hash the DLL content
            std::cout << "\nReading DLL file..." << std::endl;
            auto dllContent = readFileContent(dllFilename);
            std::cout << "DLL size: " << dllContent.size() << " bytes" << std::endl;
            
            std::cout << "\nComputing SHA-256 hash..." << std::endl;
            auto hash = computeSHA256Hash(hSession, dllContent);
            std::cout << "Hash: " << bytesToHex(hash) << std::endl;
            
            // Sign the hash using the found key
            std::cout << "\nSigning hash with ML-DSA key..." << std::endl;
            auto signature = signHash(hSession, keyInfo.hPrivateKey, hash);
            std::cout << "Signature (first 32 bytes): " << bytesToHex(signature, 32) << std::endl;
            
            // Get public key data
            auto publicKeyData = getPublicKeyData(hSession, keyInfo.hPublicKey);
            std::cout << "Public key size: " << publicKeyData.size() << " bytes" << std::endl;
            
            // Embed signature into DLL
            if (!embedSignatureInDLL(dllFilename, hash, signature, publicKeyData, paramSetInfo)) {
                throw std::runtime_error("Signature embedding failed");
            }
            
            std::cout << "\n" << std::string(60, '=') << std::endl;
            std::cout << "SUCCESS: DLL SIGNED WITH POST-QUANTUM SIGNATURE" << std::endl;
            std::cout << std::string(60, '=') << std::endl;
            std::cout << "DLL file signed with " << paramSetInfo.name << std::endl;
            std::cout << "SHA-256 hash computed and signed" << std::endl;
            std::cout << "ML-DSA signature embedded in file" << std::endl;
            std::cout << "\nSigned file: " << dllFilename << std::endl;
            // Get final file size
            std::ifstream sizeFile(dllFilename, std::ifstream::ate | std::ifstream::binary);
            size_t finalSize = 0;
            if (sizeFile.is_open()) {
                finalSize = sizeFile.tellg();
                sizeFile.close();
            }
            std::cout << "Final size: " << finalSize << " bytes" << std::endl;
            std::cout << "\nTo verify: " << argv[0] << " " << dllFilename << " --verify" << std::endl;
            
        } catch (const std::exception& e) {
            std::cerr << "\nError during signing: " << e.what() << std::endl;
            pFunctionList->C_CloseSession(hSession);
            return 1;
        }
        
        pFunctionList->C_CloseSession(hSession);
    }
    
    // Cleanup PKCS#11
    if (pFunctionList) {
        pFunctionList->C_Finalize(NULL);
    }
    
    return 0;
}
