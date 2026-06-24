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
#include "prison/configuracion.hpp"
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
    // etiquetas de titulo (a la izquierda de cada campo hundido)
    ID_T_UPTIME = 1030, ID_T_NUMCLI, ID_T_NUMROOM, ID_T_PEAK, ID_T_MEMUSED, ID_T_MEMDELTA,
    ID_T_PLAYERS = 1040,
    ID_INPUT   = 1050,   // barra de comandos (sobre Status)
    ID_TIMER   = 1,
};

// ---------------------------------------------------------------------------
//  Estado de la GUI
// ---------------------------------------------------------------------------
static HWND  g_console = nullptr, g_players = nullptr;
static HWND  g_upTime = nullptr, g_numCli = nullptr, g_numRoom = nullptr, g_peak = nullptr;
static HWND  g_memUsed = nullptr, g_memDelta = nullptr;
static HWND  g_grpStatus = nullptr, g_grpMem = nullptr;   // recuadros (Status/Memory)
static HWND  g_grpConsole = nullptr, g_grpPlayers = nullptr; // recuadros (Console/Players)
static HWND  g_carcel = nullptr;                           // nombre de la carcel (campo)
static HWND  g_input = nullptr;                            // barra de comandos (editable)
static WNDPROC g_inputProc = nullptr;                      // proc original del campo
static HFONT g_font = nullptr, g_fontMono = nullptr;
static long long g_inicio = 0;        // epoch de arranque (uptime)
static size_t    g_memBase = 0;       // memoria base para el delta

// ---------------------------------------------------------------------------
//  Utilidades
// ---------------------------------------------------------------------------
// Up Time progresivo (en ingles, palabra completa + reloj HH:MM:SS siempre):
//   < 60s  -> "N second(s) 00:00:SS"
//   < 60m  -> "N minute(s) 00:MM:SS"
//   < 24h  -> "N hour(s) HH:MM:SS"
//   >=24h  -> "N day(s) HH:MM:SS"     (con ceros, igual que la foto)
static std::string fmtUptime(long long seg) {
    if (seg < 0) seg = 0;
    long long d = seg / 86400; long long r = seg % 86400;
    long long h = r / 3600;    r %= 3600;
    long long m = r / 60;      long long s = r % 60;
    char etq[24];
    if (seg < 60)          snprintf(etq, sizeof etq, "%lld second%s", s, s == 1 ? "" : "s");
    else if (seg < 3600)   snprintf(etq, sizeof etq, "%lld minute%s", m, m == 1 ? "" : "s");
    else if (seg < 86400)  snprintf(etq, sizeof etq, "%lld hour%s",   h, h == 1 ? "" : "s");
    else                   snprintf(etq, sizeof etq, "%lld %s", d, d == 1 ? "day" : "days");
    char b[64];
    snprintf(b, sizeof b, "%s %02lld:%02lld:%02lld", etq, h, m, s);
    return b;
}

// Reloj HH:MM:SS (con ceros) para la columna "Time Online" de los jugadores.
static std::string fmtReloj(long long seg) {
    if (seg < 0) seg = 0;
    long long h = seg / 3600, m = (seg / 60) % 60, s = seg % 60;
    char b[32];
    snprintf(b, sizeof b, "%02lld:%02lld:%02lld", h, m, s);
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

// Subclase del campo de comandos: al pulsar Enter, manda lo escrito a la
// consola (y al archivo de log) y limpia el campo.
static LRESULT CALLBACK InputProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_CHAR && (w == '\r' || w == '\n')) {
        char buf[512];
        GetWindowTextA(h, buf, sizeof buf);
        if (buf[0]) {
            registro::log("> %s", buf);   // aparece en la consola y en el log
            SetWindowTextA(h, "");
        }
        return 0;                          // se traga el Enter (sin pitido)
    }
    return CallWindowProcA(g_inputProc, h, m, w, l);
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
    // Recuadros Console / Players: el titulo arriba-izquierda y el borde rodea el panel.
    g_grpConsole = CreateWindowExA(0, "BUTTON", "Console", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        0, 0, 10, 10, hwnd, nullptr, nullptr, nullptr);
    SendMessageA(g_grpConsole, WM_SETFONT, (WPARAM)g_font, TRUE);
    g_grpPlayers = CreateWindowExA(0, "BUTTON", "Players", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        0, 0, 10, 10, hwnd, nullptr, nullptr, nullptr);
    SendMessageA(g_grpPlayers, WM_SETFONT, (WPARAM)g_font, TRUE);

    // Nombre de la carcel: solo hay una, asi que es texto fijo (no desplegable).
    // Va JUSTO DEBAJO del texto "Console", en un campo con borde (como antes).
    {
        std::string carcel = cfg().nombrePrision.empty() ? "La Prision" : cfg().nombrePrision;
        g_carcel = CreateWindowExA(WS_EX_CLIENTEDGE, "STATIC", carcel.c_str(),
            WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
            0, 0, 10, 20, hwnd, nullptr, nullptr, nullptr);
        SendMessageA(g_carcel, WM_SETFONT, (WPARAM)g_font, TRUE);
    }

    g_console = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        0, 0, 10, 10, hwnd, (HMENU)ID_CONSOLE, nullptr, nullptr);
    SendMessageA(g_console, WM_SETFONT, (WPARAM)g_fontMono, TRUE);

    g_players = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        0, 0, 10, 10, hwnd, (HMENU)ID_PLAYERS, nullptr, nullptr);
    ListView_SetExtendedListViewStyle(g_players, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    SendMessageA(g_players, WM_SETFONT, (WPARAM)g_font, TRUE);
    const char* cols[] = { "Nick", "Ping", "Room", "Time Online", "Time Online (server.client)" };
    int anchos[] = { 120, 44, 90, 90, 175 };
    for (int i = 0; i < 5; i++) {
        LVCOLUMNA c; memset(&c, 0, sizeof c);
        c.mask = LVCF_TEXT | LVCF_WIDTH; c.pszText = (LPSTR)cols[i]; c.cx = anchos[i];
        ListView_InsertColumn(g_players, i, &c);
    }

    // Estado y memoria (abajo): titulo (etiqueta) + campo HUNDIDO con el valor.
    auto campo = [&](int id) -> HWND {
        HWND e = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_READONLY | ES_CENTER,
            0, 0, 10, 18, hwnd, (HMENU)(INT_PTR)id, nullptr, nullptr);
        SendMessageA(e, WM_SETFONT, (WPARAM)g_font, TRUE);
        return e;
    };
    etiqueta(hwnd, "Up Time:",     ID_T_UPTIME,  0, 0, 80, 16);
    etiqueta(hwnd, "Num Clients:", ID_T_NUMCLI,  0, 0, 80, 16);
    etiqueta(hwnd, "Num Rooms:",   ID_T_NUMROOM, 0, 0, 80, 16);
    etiqueta(hwnd, "Peak Clients:",ID_T_PEAK,    0, 0, 80, 16);
    etiqueta(hwnd, "Used Memory:", ID_T_MEMUSED, 0, 0, 80, 16);
    etiqueta(hwnd, "Memory Delta:",ID_T_MEMDELTA,0, 0, 80, 16);
    g_upTime  = campo(ID_UPTIME);
    g_numCli  = campo(ID_NUMCLI);
    g_numRoom = campo(ID_NUMROOM);
    g_peak    = campo(ID_PEAK);
    g_memUsed = campo(ID_MEMUSED);
    g_memDelta= campo(ID_MEMDELTA);

    HWND fr = CreateWindowExA(0, "BUTTON", "Freeze Players", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        0, 0, 130, 18, hwnd, (HMENU)ID_FREEZE, nullptr, nullptr);
    SendMessageA(fr, WM_SETFONT, (WPARAM)g_font, TRUE);
    HWND lk = CreateWindowExA(0, "BUTTON", "Server Locked", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        0, 0, 130, 18, hwnd, (HMENU)ID_LOCKED, nullptr, nullptr);
    SendMessageA(lk, WM_SETFONT, (WPARAM)g_font, TRUE);
    HWND rb = CreateWindowExA(0, "BUTTON", "Reset Memory Delta", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 150, 22, hwnd, (HMENU)ID_RESETDELTA, nullptr, nullptr);
    SendMessageA(rb, WM_SETFONT, (WPARAM)g_font, TRUE);

    // Barra de comandos (editable) encima de Status, como en la foto.
    g_input = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, 0, 10, 20, hwnd, (HMENU)ID_INPUT, nullptr, nullptr);
    SendMessageA(g_input, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
    g_inputProc = (WNDPROC)SetWindowLongPtrA(g_input, GWLP_WNDPROC, (LONG_PTR)InputProc);
}

// Reubica los controles segun el tamano de la ventana.
static void colocar(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;
    auto pon = [&](int id, int x, int y, int w, int h) {
        SetWindowPos(GetDlgItem(hwnd, id), nullptr, x, y, w, h, SWP_NOZORDER);
    };

    int bottomH = 128;
    int topY = 4;
    int topH = H - bottomH - topY - 6;     // alto de los recuadros Console/Players
    if (topH < 80) topH = 80;
    int half = (W - 24) / 2;
    int barH = 22;                          // alto de la barra de comandos (dentro de Console)

    // Recuadros Console (izq) y Players (der): el borde rodea cada panel.
    SetWindowPos(g_grpConsole, nullptr, 8, topY, half, topH, SWP_NOZORDER);
    SetWindowPos(g_grpPlayers, nullptr, 8 + half + 8, topY, half, topH, SWP_NOZORDER);

    // Interior de Console: nombre de la carcel arriba (dentro del marco) + consola debajo.
    int cInX = 16, cInW = half - 16;
    int cInTop = topY + 18;                 // justo bajo el titulo "Console"
    SetWindowPos(g_carcel,  nullptr, cInX, cInTop, cInW, 20, SWP_NOZORDER);
    int conY = cInTop + 26;
    int barY = topY + topH - 10 - barH;     // barra al fondo del recuadro Console
    int conH = barY - conY - 4;
    SetWindowPos(g_console, nullptr, cInX, conY, cInW, conH, SWP_NOZORDER);
    // Barra de comandos: DEBAJO del chat, dentro de Console y a su mismo ancho.
    SetWindowPos(g_input,   nullptr, cInX, barY, cInW, barH, SWP_NOZORDER);

    // Interior de Players: la lista ocupa el recuadro.
    int pInX = 8 + half + 8 + 8;
    int pInW = half - 16;
    int pInTop = topY + 18;
    int pInH = topY + topH - pInTop - 10;
    SetWindowPos(g_players, nullptr, pInX, pInTop, pInW, pInH, SWP_NOZORDER);

    // La ultima columna rellena el ancho restante (sin cabecera vacia a la derecha).
    {
        int otras = 120 + 44 + 90 + 90;        // Nick + Ping + Room + Time Online
        int ultima = pInW - 6 - otras;
        if (ultima < 140) ultima = 140;
        ListView_SetColumnWidth(g_players, 4, ultima);
    }

    // Recuadros Status / Memory (con sus controles dentro).
    int gy = topY + topH + 6;           // borde superior de los recuadros
    int gh = bottomH - 12;              // alto del recuadro
    int statusW = 340;
    SetWindowPos(g_grpStatus, nullptr, 8, gy, statusW, gh, SWP_NOZORDER);
    SetWindowPos(g_grpMem, nullptr, 8 + statusW + 8, gy,
                 W - (8 + statusW + 8) - 8, gh, SWP_NOZORDER);

    int sx = 16, sy = gy + 16;          // interior de Status
    int vx = sx + 80;                   // x de los campos de valor
    int longW = statusW - (vx - 8) - 12;// Up Time casi hasta el final del recuadro
    pon(ID_T_UPTIME, sx, sy + 2,  74, 14);  pon(ID_UPTIME, vx, sy,      longW, 18);
    pon(ID_T_NUMCLI, sx, sy + 26, 74, 14);  pon(ID_NUMCLI, vx, sy + 24, 70,    18);
    pon(ID_T_NUMROOM,sx, sy + 50, 74, 14);  pon(ID_NUMROOM,vx, sy + 48, 70,    18);
    pon(ID_T_PEAK,   sx, sy + 74, 74, 14);  pon(ID_PEAK,   vx, sy + 72, 70,    18);
    // casillas a la derecha (alineadas con Num Clients / Num Rooms)
    pon(ID_FREEZE,   vx + 86, sy + 25, 140, 18);
    pon(ID_LOCKED,   vx + 86, sy + 49, 140, 18);

    int mx = 8 + statusW + 8 + 10, my = gy + 16;   // interior de Memory
    pon(ID_T_MEMUSED, mx, my + 2,  84, 14);  pon(ID_MEMUSED, mx + 88, my,      150, 18);
    pon(ID_T_MEMDELTA,mx, my + 26, 84, 14);  pon(ID_MEMDELTA,mx + 88, my + 24, 150, 18);
    pon(ID_RESETDELTA,mx, my + 54, 160, 22);
}

// Refresca estado + lista de jugadores (cada segundo).
static void refrescar() {
    std::vector<std::string> lineas;
    monitor::drenarLog(lineas);
    appendConsola(lineas);

    setTexto(g_upTime,  fmtUptime((long long)time(nullptr) - g_inicio));
    setTexto(g_numCli,  std::to_string(monitor::numClientes()));
    setTexto(g_numRoom, "1");
    setTexto(g_peak,    std::to_string(monitor::picoClientes()));

    size_t mem = memoriaUsada();
    char mb[64];
    snprintf(mb, sizeof mb, "%zu KB", mem / 1024);
    setTexto(g_memUsed, mb);
    long long delta = (long long)mem - (long long)g_memBase;
    snprintf(mb, sizeof mb, "%lld KB", delta / 1024);
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
        std::string on = fmtReloj(ahora - js[i].t0);
        ListView_SetItemText(g_players, (int)i, 3, (LPSTR)on.c_str());
        char sc[40];
        snprintf(sc, sizeof sc, "%u.%u", js[i].idServidor, (unsigned)(js[i].clave & 0xffffu));
        ListView_SetItemText(g_players, (int)i, 4, (LPSTR)sc);
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

    // Contenido estatico del mundo (Objectinfo) creado una vez al arrancar,
    // con los logs al estilo del servidor original.
    mundo.prepararContenido();
    registro::log("--- Connected to Login Server ---");
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

    HWND hwnd = CreateWindowExA(0, "PrisonServerWnd", "Prison 300",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1070, 600,
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
