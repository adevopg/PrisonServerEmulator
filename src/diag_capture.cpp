// PrisonServer diagnostic capture tool
// Listens on UDP + TCP ports 25666 (login) and 25667 (updates),
// hex-dumps every datagram/segment received from Carcelclient.exe.
// Purpose: reverse-engineer the live wire protocol.
//
// Build (from a "x64 Native Tools" prompt or after vcvars64.bat):
//   cl /EHsc /O2 /std:c++17 src\diag_capture.cpp /Fe:bin\diag_capture.exe ws2_32.lib
//
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")

static std::mutex g_logMtx;
static FILE*      g_logFile = nullptr;

static void ts(char* buf, size_t n) {
    SYSTEMTIME st; GetLocalTime(&st);
    snprintf(buf, n, "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static void logLine(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_logMtx);
    fputs(s.c_str(), stdout); fputc('\n', stdout); fflush(stdout);
    if (g_logFile) { fputs(s.c_str(), g_logFile); fputc('\n', g_logFile); fflush(g_logFile); }
}

static void hexDump(const char* tag, const char* who, const uint8_t* data, int len) {
    char t[32]; ts(t, sizeof t);
    char hdr[256];
    snprintf(hdr, sizeof hdr, "[%s] %s %s  len=%d", t, tag, who, len);
    std::string out = hdr; out += "\n";
    char line[128];
    for (int i = 0; i < len; i += 16) {
        int n = 0;
        n += snprintf(line + n, sizeof line - n, "  %04x  ", i);
        for (int j = 0; j < 16; ++j) {
            if (i + j < len) n += snprintf(line + n, sizeof line - n, "%02x ", data[i + j]);
            else            n += snprintf(line + n, sizeof line - n, "   ");
            if (j == 7) n += snprintf(line + n, sizeof line - n, " ");
        }
        n += snprintf(line + n, sizeof line - n, " |");
        for (int j = 0; j < 16 && i + j < len; ++j) {
            uint8_t c = data[i + j];
            line[n++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        line[n++] = '|'; line[n] = 0;
        out += line; out += "\n";
    }
    logLine(out);
}

static void udpListener(uint16_t port, const char* tag) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { printf("UDP socket fail %d\n", WSAGetLastError()); return; }
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (sockaddr*)&a, sizeof a) == SOCKET_ERROR) {
        printf("UDP bind %u fail %d\n", port, WSAGetLastError()); closesocket(s); return;
    }
    { char b[64]; snprintf(b,sizeof b,"[*] UDP listening on 0.0.0.0:%u  (%s)", port, tag); logLine(b); }
    std::vector<uint8_t> buf(65536);
    for (;;) {
        sockaddr_in from{}; int fl = sizeof from;
        int n = recvfrom(s, (char*)buf.data(), (int)buf.size(), 0, (sockaddr*)&from, &fl);
        if (n == SOCKET_ERROR) { printf("UDP %u recv err %d\n", port, WSAGetLastError()); continue; }
        char who[64]; char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
        snprintf(who, sizeof who, "UDP:%u <- %s:%u", port, ip, ntohs(from.sin_port));
        hexDump(tag, who, buf.data(), n);
        // Echo nothing yet; we are only observing.
    }
}

static void tcpConn(SOCKET c, uint16_t port, const char* tag, sockaddr_in from) {
    char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
    char who[64]; snprintf(who, sizeof who, "TCP:%u <- %s:%u", port, ip, ntohs(from.sin_port));
    std::vector<uint8_t> buf(65536);
    for (;;) {
        int n = recv(c, (char*)buf.data(), (int)buf.size(), 0);
        if (n <= 0) { char b[96]; snprintf(b,sizeof b,"[*] %s closed", who); logLine(b); break; }
        hexDump(tag, who, buf.data(), n);
    }
    closesocket(c);
}

static void tcpListener(uint16_t port, const char* tag) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { printf("TCP socket fail %d\n", WSAGetLastError()); return; }
    BOOL yes = TRUE; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof yes);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (sockaddr*)&a, sizeof a) == SOCKET_ERROR) {
        printf("TCP bind %u fail %d\n", port, WSAGetLastError()); closesocket(s); return;
    }
    listen(s, 8);
    { char b[64]; snprintf(b,sizeof b,"[*] TCP listening on 0.0.0.0:%u  (%s)", port, tag); logLine(b); }
    for (;;) {
        sockaddr_in from{}; int fl = sizeof from;
        SOCKET c = accept(s, (sockaddr*)&from, &fl);
        if (c == INVALID_SOCKET) continue;
        std::thread(tcpConn, c, port, tag, from).detach();
    }
}

int main() {
    WSADATA wsa; if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { printf("WSAStartup fail\n"); return 1; }
    g_logFile = fopen("capture.log", "a");
    logLine("==================== diag_capture start ====================");
    std::vector<std::thread> ts_;
    ts_.emplace_back(udpListener, 25666, "LOGIN");
    ts_.emplace_back(udpListener, 25667, "UPDATES");
    ts_.emplace_back(tcpListener, 25666, "LOGIN");
    ts_.emplace_back(tcpListener, 25667, "UPDATES");
    for (auto& t : ts_) t.join();
    WSACleanup();
    return 0;
}
