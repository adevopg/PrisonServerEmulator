// ============================================================================
//  main.cpp  —  PrisonServer con VENTANA (GUI), sin consola
// ============================================================================
//
//  El servidor ahora arranca como una aplicacion de ventana de Windows (igual
//  que el programa oficial de la imagen): un panel "Console" con el log, una
//  lista "Players" con los jugadores conectados, y abajo el estado (uptime,
//  clientes, salas, pico) y la memoria usada.
//
//  La red (Boost.Asio) y los tres servidores corren en HILOS aparte; el hilo
//  principal se queda con el bucle de mensajes de la ventana. Cada segundo, un
//  temporizador vuelca el log y refresca el estado y la lista de jugadores.
// ============================================================================
#include "prison/registro.hpp"
#include "prison/monitor.hpp"
#include "prison/base_datos.hpp"
#include "prison/servidor_login.hpp"
#include "prison/servidor_mundo.hpp"
#include "prison/servidor_updates.hpp"

#include <boost/asio.hpp>
#include <thread>
#include <string>
#include <vector>
#include <ctime>

#include <windows.h>
#include <commctrl.h>
#include <psapi.h>

using namespace prison;

// ---------------------------------------------------------------------------
//  IDs de los controles de la ventana
// ---------------------------------------------------------------------------
enum {
    ID_CONSOLE = 1001,   // edit multilinea con el log
    ID_PLAYERS = 1002,   // ListView de jugadores
    ID_UPTIME  = 1010, ID_NUMCLI, ID_NUMROOM, ID_PEAK,
    ID_MEMUSED, ID_MEMDELTA, ID_RESETDELTA,
    ID_FREEZE, ID_LOCKED,
    ID_TIMER   = 1,
};

// ---------------------------------------------------------------------------
//  Estado de la GUI
// ---------------------------------------------------------------------------
static HWND  g_console = nullptr, g_players = nullptr;
static HWND  g_upTime = nullptr, g_numCli = nullptr, g_numRoom = nullptr, g_peak = nullptr;
static HWND  g_memUsed = nullptr, g_memDelta = nullptr;
static HWND  g_grpStatus = nullptr, g_grpMem = nullptr;   // recuadros
static HFONT g_font = nullptr, g_fontMono = nullptr;
static long long g_inicio = 0;        // epoch de arranque (uptime)
static size_t    g_memBase = 0;       // memoria base para el delta

// ---------------------------------------------------------------------------
//  Utilidades
// ---------------------------------------------------------------------------
static std::string fmtDuracion(long long seg) {
    if (seg < 0) seg = 0;
    long long d = seg / 86400; seg %= 86400;
    long long h = seg / 3600;  seg %= 3600;
    long long m = seg / 60;    long long s = seg % 60;
    char b[64];
    if (d > 0) snprintf(b, sizeof b, "%lld dias %02lld:%02lld:%02lld", d, h, m, s);
    else       snprintf(b, sizeof b, "%02lld:%02lld:%02lld", h, m, s);
    return b;
}

static size_t memoriaUsada() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof pmc))
        return pmc.WorkingSetSize;
    return 0;
}

static void setTexto(HWND h, const std::string& s) { SetWindowTextA(h, s.c_str()); }

// Anade lineas al final del Edit de consola (manteniendo el scroll abajo).
static void appendConsola(const std::vector<std::string>& lineas) {
    if (lineas.empty()) return;
    std::string add;
    for (auto& l : lineas) { add += l; add += "\r\n"; }
    int len = GetWindowTextLengthA(g_console);
    SendMessageA(g_console, EM_SETSEL, len, len);
    SendMessageA(g_console, EM_REPLACESEL, FALSE, (LPARAM)add.c_str());
    // Recortar si crece demasiado.
    len = GetWindowTextLengthA(g_console);
    if (len > 120000) {
        SendMessageA(g_console, EM_SETSEL, 0, len - 60000);
        SendMessageA(g_console, EM_REPLACESEL, FALSE, (LPARAM)"");
        len = GetWindowTextLengthA(g_console);
        SendMessageA(g_console, EM_SETSEL, len, len);
    }
    SendMessageA(g_console, WM_VSCROLL, SB_BOTTOM, 0);
}

// ---------------------------------------------------------------------------
//  Crear los controles hijos
// ---------------------------------------------------------------------------
static HWND etiqueta(HWND p, const char* txt, int id, int x, int y, int w, int h) {
    HWND s = CreateWindowExA(0, "STATIC", txt, WS_CHILD | WS_VISIBLE,
                             x, y, w, h, p, (HMENU)(INT_PTR)id, nullptr, nullptr);
    SendMessageA(s, WM_SETFONT, (WPARAM)g_font, TRUE);
    return s;
}

static void crearControles(HWND hwnd) {
    g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    g_fontMono = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             0, 0, 0, FIXED_PITCH | FF_MODERN, "Consolas");

    // Recuadros (group box) PRIMERO, para que queden DETRAS de sus etiquetas.
    g_grpStatus = CreateWindowExA(0, "BUTTON", "Status", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        0, 0, 10, 10, hwnd, nullptr, nullptr, nullptr);
    SendMessageA(g_grpStatus, WM_SETFONT, (WPARAM)g_font, TRUE);
    g_grpMem = CreateWindowExA(0, "BUTTON", "Memory", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        0, 0, 10, 10, hwnd, nullptr, nullptr, nullptr);
    SendMessageA(g_grpMem, WM_SETFONT, (WPARAM)g_font, TRUE);

    etiqueta(hwnd, "Console", 0, 8, 4, 120, 16);

    g_console = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        0, 0, 10, 10, hwnd, (HMENU)ID_CONSOLE, nullptr, nullptr);
    SendMessageA(g_console, WM_SETFONT, (WPARAM)g_fontMono, TRUE);

    g_players = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        0, 0, 10, 10, hwnd, (HMENU)ID_PLAYERS, nullptr, nullptr);
    ListView_SetExtendedListViewStyle(g_players, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    SendMessageA(g_players, WM_SETFONT, (WPARAM)g_font, TRUE);
    const char* cols[] = { "Nick", "Ping", "Room", "Time Online" };
    int anchos[] = { 140, 50, 120, 110 };
    for (int i = 0; i < 4; i++) {
        LVCOLUMNA c; memset(&c, 0, sizeof c);
        c.mask = LVCF_TEXT | LVCF_WIDTH; c.pszText = (LPSTR)cols[i]; c.cx = anchos[i];
        ListView_InsertColumn(g_players, i, &c);
    }

    // Estado y memoria (abajo).
    g_upTime  = etiqueta(hwnd, "Up Time: -",        ID_UPTIME,  0, 0, 260, 16);
    g_numCli  = etiqueta(hwnd, "Num Clients: 0",    ID_NUMCLI,  0, 0, 160, 16);
    g_numRoom = etiqueta(hwnd, "Num Rooms: 1",      ID_NUMROOM, 0, 0, 160, 16);
    g_peak    = etiqueta(hwnd, "Peak Clients: 0",   ID_PEAK,    0, 0, 160, 16);
    g_memUsed = etiqueta(hwnd, "Used Memory: -",    ID_MEMUSED, 0, 0, 260, 16);
    g_memDelta= etiqueta(hwnd, "Memory Delta: 0",   ID_MEMDELTA,0, 0, 260, 16);

    HWND fr = CreateWindowExA(0, "BUTTON", "Freeze Players", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        0, 0, 130, 18, hwnd, (HMENU)ID_FREEZE, nullptr, nullptr);
    SendMessageA(fr, WM_SETFONT, (WPARAM)g_font, TRUE);
    HWND lk = CreateWindowExA(0, "BUTTON", "Server Locked", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        0, 0, 130, 18, hwnd, (HMENU)ID_LOCKED, nullptr, nullptr);
    SendMessageA(lk, WM_SETFONT, (WPARAM)g_font, TRUE);
    HWND rb = CreateWindowExA(0, "BUTTON", "Reset Memory Delta", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 150, 22, hwnd, (HMENU)ID_RESETDELTA, nullptr, nullptr);
    SendMessageA(rb, WM_SETFONT, (WPARAM)g_font, TRUE);
}

// Reubica los controles segun el tamano de la ventana.
static void colocar(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;
    int bottomH = 104;
    int paneTop = 22, paneH = H - bottomH - paneTop - 6;
    if (paneH < 60) paneH = 60;
    int half = (W - 24) / 2;
    SetWindowPos(g_console, nullptr, 8, paneTop, half, paneH, SWP_NOZORDER);
    SetWindowPos(g_players, nullptr, 8 + half + 8, paneTop, half, paneH, SWP_NOZORDER);

    // Recuadros Status / Memory (con sus controles dentro).
    int gy = paneTop + paneH + 6;       // borde superior de los recuadros
    int gh = bottomH - 12;              // alto del recuadro
    int statusW = 330;
    SetWindowPos(g_grpStatus, nullptr, 8, gy, statusW, gh, SWP_NOZORDER);
    SetWindowPos(g_grpMem, nullptr, 8 + statusW + 8, gy,
                 W - (8 + statusW + 8) - 8, gh, SWP_NOZORDER);

    int sx = 18, sy = gy + 18;          // interior de Status
    SetWindowPos(g_upTime,  nullptr, sx,       sy,      300, 16, SWP_NOZORDER);
    SetWindowPos(g_numCli,  nullptr, sx,       sy + 20, 150, 16, SWP_NOZORDER);
    SetWindowPos(g_numRoom, nullptr, sx + 150, sy + 20, 150, 16, SWP_NOZORDER);
    SetWindowPos(g_peak,    nullptr, sx,       sy + 40, 150, 16, SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hwnd, ID_FREEZE), nullptr, sx + 150, sy + 38, 140, 18, SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hwnd, ID_LOCKED), nullptr, sx + 150, sy + 58, 140, 18, SWP_NOZORDER);

    int mx = 8 + statusW + 8 + 10, my = gy + 18;   // interior de Memory
    SetWindowPos(g_memUsed,  nullptr, mx, my,      240, 16, SWP_NOZORDER);
    SetWindowPos(g_memDelta, nullptr, mx, my + 20, 240, 16, SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hwnd, ID_RESETDELTA), nullptr, mx, my + 44, 150, 22, SWP_NOZORDER);
}

// Refresca estado + lista de jugadores (cada segundo).
static void refrescar() {
    std::vector<std::string> lineas;
    monitor::drenarLog(lineas);
    appendConsola(lineas);

    setTexto(g_upTime,  "Up Time: " + fmtDuracion((long long)time(nullptr) - g_inicio));
    setTexto(g_numCli,  "Num Clients: " + std::to_string(monitor::numClientes()));
    setTexto(g_peak,    "Peak Clients: " + std::to_string(monitor::picoClientes()));

    size_t mem = memoriaUsada();
    char mb[64];
    snprintf(mb, sizeof mb, "Used Memory: %zu KB", mem / 1024);
    setTexto(g_memUsed, mb);
    long long delta = (long long)mem - (long long)g_memBase;
    snprintf(mb, sizeof mb, "Memory Delta: %lld KB", delta / 1024);
    setTexto(g_memDelta, mb);

    auto js = monitor::jugadores();
    ListView_DeleteAllItems(g_players);
    long long ahora = (long long)time(nullptr);
    for (size_t i = 0; i < js.size(); i++) {
        LVITEMA it; memset(&it, 0, sizeof it);
        it.mask = LVIF_TEXT; it.iItem = (int)i;
        it.pszText = (LPSTR)js[i].nick.c_str();
        ListView_InsertItem(g_players, &it);
        char tmp[32]; snprintf(tmp, sizeof tmp, "%d", js[i].ping);
        ListView_SetItemText(g_players, (int)i, 1, tmp);
        ListView_SetItemText(g_players, (int)i, 2, (LPSTR)js[i].sala.c_str());
        std::string on = fmtDuracion(ahora - js[i].t0);
        ListView_SetItemText(g_players, (int)i, 3, (LPSTR)on.c_str());
    }
}

// ---------------------------------------------------------------------------
//  WindowProc
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:   crearControles(hwnd); SetTimer(hwnd, ID_TIMER, 1000, nullptr); return 0;
    case WM_SIZE:     colocar(hwnd); return 0;
    case WM_TIMER:    if (wp == ID_TIMER) refrescar(); return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == ID_RESETDELTA) { g_memBase = memoriaUsada(); refrescar(); }
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mm = (MINMAXINFO*)lp;
        mm->ptMinTrackSize.x = 700; mm->ptMinTrackSize.y = 460;
        return 0;
    }
    case WM_DESTROY:  PostQuitMessage(0); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
//  Arranque de los servidores (en hilos) + ventana
// ---------------------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow) {
    registro::abrir("login_server.log");
    g_inicio = (long long)time(nullptr);

    static BaseDatos bd;
    if (bd.conectar()) registro::log("MySQL conectado (base 'prison', usuario Inna)");
    else               registro::log("MySQL FALLO al conectar: %s", bd.ultimoError());

    static boost::asio::io_context io;
    static ServidorLogin   login(io, bd);
    static ServidorUpdates updates(io);
    static ServidorMundo   mundo(io);

    if (!login.iniciar()) {
        MessageBoxA(nullptr, "No se pudo abrir el ServidorLogin (UDP 25666)", "PrisonServer", MB_ICONERROR);
        return 1;
    }
    updates.iniciar();
    mundo.iniciar();
    registro::log("The Brave Game Server RUNNING");

    std::thread([&]{ login.ejecutar();   }).detach();
    std::thread([&]{ updates.ejecutar(); }).detach();
    std::thread([&]{ mundo.ejecutar();   }).detach();

    g_memBase = memoriaUsada();

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSA wc; memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "PrisonServerWnd";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(0, "PrisonServerWnd", "PrisonServer - La Prision",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 900, 600,
        nullptr, nullptr, hInst, nullptr);
    ShowWindow(hwnd, nCmdShow ? nCmdShow : SW_SHOW);
    UpdateWindow(hwnd);

    MSG m;
    while (GetMessageA(&m, nullptr, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageA(&m);
    }
    return 0;
}
