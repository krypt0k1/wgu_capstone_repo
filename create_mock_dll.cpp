/*
 * Simple Mock DLL Generator for ML-DSA Code Signing Tests
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

bool createSimpleMockDLL(const std::string& filename) {
    std::cout << "Creating simple mock DLL: " << filename << std::endl;
    
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Could not create file " << filename << std::endl;
        return false;
    }
    
    // Simple DOS header with MZ signature
    const unsigned char dosHeader[] = {
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
    };
    file.write(reinterpret_cast<const char*>(dosHeader), sizeof(dosHeader));
    
    // DOS stub
    const char dosStub[] = "This program cannot be run in DOS mode.\r\n$";
    file.write(dosStub, strlen(dosStub));
    
    // Pad to PE header
    std::vector<char> padding(0x80 - sizeof(dosHeader) - strlen(dosStub), 0);
    file.write(padding.data(), padding.size());
    
    // PE signature
    file.write("PE\0\0", 4);
    
    // Minimal COFF header for DLL
    const unsigned char coffHeader[] = {
        0x4C, 0x01,  // Machine: i386
        0x01, 0x00,  // Number of sections
        0x78, 0x56, 0x34, 0x12,  // Timestamp
        0x00, 0x00, 0x00, 0x00,  // Symbol table offset
        0x00, 0x00, 0x00, 0x00,  // Number of symbols
        0xE0, 0x00,  // Optional header size
        0x02, 0x22   // Characteristics: DLL + Executable
    };
    file.write(reinterpret_cast<const char*>(coffHeader), sizeof(coffHeader));
    
    // Optional header (PE32)
    const unsigned char optHeader[] = {
        0x0B, 0x01,  // Magic: PE32
        0x0E, 0x00,  // Linker version
        0x00, 0x10, 0x00, 0x00,  // Size of code
        0x00, 0x10, 0x00, 0x00,  // Size of initialized data
        0x00, 0x00, 0x00, 0x00,  // Size of uninitialized data
        0x00, 0x10, 0x00, 0x00,  // Entry point
        0x00, 0x10, 0x00, 0x00,  // Base of code
        0x00, 0x20, 0x00, 0x00,  // Base of data
        0x00, 0x00, 0x00, 0x10,  // Image base
        0x00, 0x10, 0x00, 0x00,  // Section alignment
        0x00, 0x02, 0x00, 0x00,  // File alignment
        0x06, 0x00, 0x00, 0x00,  // OS version
        0x01, 0x00, 0x00, 0x00,  // Image version
        0x06, 0x00, 0x00, 0x00,  // Subsystem version
        0x00, 0x00, 0x00, 0x00,  // Reserved
        0x00, 0x30, 0x00, 0x00,  // Size of image
        0x00, 0x04, 0x00, 0x00,  // Size of headers
        0x00, 0x00, 0x00, 0x00,  // Checksum
        0x02, 0x00,              // Subsystem: GUI
        0x00, 0x80,              // DLL characteristics
        0x00, 0x00, 0x10, 0x00,  // Stack reserve
        0x00, 0x10, 0x00, 0x00,  // Stack commit
        0x00, 0x00, 0x10, 0x00,  // Heap reserve
        0x00, 0x10, 0x00, 0x00,  // Heap commit
        0x00, 0x00, 0x00, 0x00,  // Loader flags
        0x10, 0x00, 0x00, 0x00   // Number of RVAs
    };
    file.write(reinterpret_cast<const char*>(optHeader), sizeof(optHeader));
    
    // Data directories (16 entries, all zeros)
    std::vector<char> dataDirectories(16 * 8, 0);
    file.write(dataDirectories.data(), dataDirectories.size());
    
    // Section header for .text
    const unsigned char sectionHeader[] = {
        0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00,  // ".text"
        0x00, 0x10, 0x00, 0x00,  // Virtual size
        0x00, 0x10, 0x00, 0x00,  // Virtual address
        0x00, 0x02, 0x00, 0x00,  // Size of raw data
        0x00, 0x04, 0x00, 0x00,  // Pointer to raw data
        0x00, 0x00, 0x00, 0x00,  // Relocations
        0x00, 0x00, 0x00, 0x00,  // Line numbers
        0x00, 0x00, 0x00, 0x00,  // Relocation/line number counts
        0x20, 0x00, 0x00, 0x60   // Characteristics: Code + Execute + Read
    };
    file.write(reinterpret_cast<const char*>(sectionHeader), sizeof(sectionHeader));
    
    // Pad to section data
    size_t currentPos = file.tellp();
    std::vector<char> headerPadding(0x400 - currentPos, 0);
    file.write(headerPadding.data(), headerPadding.size());
    
    // Section content (simple function)
    const unsigned char code[] = {
        0x55,        // push ebp
        0x8B, 0xEC,  // mov ebp, esp
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0x5D,        // pop ebp
        0xC3         // ret
    };
    file.write(reinterpret_cast<const char*>(code), sizeof(code));
    
    // Add some mock data
    std::string mockData = "Mock DLL for ML-DSA testing - Created for code signing demonstration\n";
    file.write(mockData.c_str(), mockData.length());
    
    // Pad section to file alignment
    size_t sectionSize = sizeof(code) + mockData.length();
    std::vector<char> sectionPadding(0x200 - sectionSize, 0);
    file.write(sectionPadding.data(), sectionPadding.size());
    
    file.close();
    return true;
}

int main() {
    std::cout << "Mock DLL Generator for ML-DSA Code Signing Tests" << std::endl;
    std::cout << "===============================================" << std::endl;
    
    if (!createSimpleMockDLL("mock.dll")) {
        return 1;
    }
    
    // Get file size
    std::ifstream file("mock.dll", std::ifstream::ate | std::ifstream::binary);
    size_t fileSize = file.tellg();
    file.close();
    
    std::cout << "Mock DLL created successfully:" << std::endl;
    std::cout << "  Filename: mock.dll" << std::endl;
    std::cout << "  Size: " << fileSize << " bytes" << std::endl;
    std::cout << "  Format: Windows PE32 DLL" << std::endl;
    
    std::cout << "\nReady for signing with:" << std::endl;
    std::cout << "  preload -s SoftcardName mldsa_dll_signer.exe mock.dll \"KeyName\"" << std::endl;
    
    return 0;
}
