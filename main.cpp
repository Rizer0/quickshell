#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <vector>
#include <cstring>


void printShellcodeAsC(const std::vector<unsigned char>& data) {
    std::cout << "unsigned char sc[] = {\n    ";
    for (size_t i = 0; i < data.size(); ++i) {
        std::cout << "0x" << std::hex << std::setw(2)
            << std::setfill('0') << static_cast<int>(data[i]);
        if (i != data.size() - 1) std::cout << ", ";
        if ((i + 1) % 12 == 0) std::cout << "\n    ";
    }
    std::cout << "\n};\n";
}

void printShellcodeAsPython(const std::vector<unsigned char>& data) {
    std::cout << "sc = b\"";
    for (unsigned char c : data) {
        std::cout << "\\x" << std::hex << std::setw(2)
            << std::setfill('0') << static_cast<int>(c);
    }
    std::cout << "\"\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <shellcode_file> [c|py]\n";
        return 1;
    }
    std::cout << R"(

        ____     
     .-'    '-.  
   .'          '. 
  /   O      O   \ 
 :           `    :
 |                |   
 :    .------.    : 
  \  '        '  /  
   '.          .'
     '-.__.__.-'   

       quickshell  -  @Nullbyte0x

)" << std::endl;

    const char* filename = argv[1];
    std::string format = (argc >= 3) ? argv[2] : "none";

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "[-] Failed to open file: " << filename << "\n";
        return 1;
    }

    std::vector<unsigned char> shellcode(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    if (shellcode.empty()) {
        std::cerr << "[-] Shellcode is empty!\n";
        return 1;
    }

    std::cout << "[+] Shellcode length: " << shellcode.size() << " bytes\n";

    if (format == "c") {
        printShellcodeAsC(shellcode);
    }
    else if (format == "py") {
        printShellcodeAsPython(shellcode);
    }

    void* exec_mem = VirtualAlloc(nullptr, shellcode.size(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        std::cerr << "[-] VirtualAlloc failed: " << GetLastError() << "\n";
        return 1;
    }

    std::memcpy(exec_mem, shellcode.data(), shellcode.size());

    std::cout << "[*] Executing shellcode...\n";
    ((void(*)())exec_mem)();

    return 0;
}
