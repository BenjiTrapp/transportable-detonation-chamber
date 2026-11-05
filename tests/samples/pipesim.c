/*
 * pipesim - harmless named-pipe test sample for the Named Pipes feature.
 *
 * Mimics the pipe pattern of a Cobalt Strike SMB beacon without doing
 * anything else: the parent creates \\.\pipe\msagent_<random hex> and starts
 * a child copy of itself ("pipesim.exe child <pipe>") that connects. Every
 * 2 s the child sends "beacon <n>" and the parent answers "task <n>", for
 * 60 s. No network, no persistence, no files.
 *
 * The child waits 3 s before connecting so that an armed interception
 * session has time to attach to the new pipe.
 *
 * Build: zig cc -target x86_64-windows-gnu -O2 -o pipesim.exe pipesim.c
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define RUNTIME_MS 60000
#define INTERVAL_MS 2000
#define CONNECT_DELAY_MS 3000
#define WATCHDOG_MS 90000

static DWORD WINAPI watchdog(LPVOID arg) {
    (void)arg;
    Sleep(WATCHDOG_MS);
    printf("watchdog: giving up\n");
    ExitProcess(2);
    return 0;
}

static int run_child(const char *pipe) {
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD start, mode = PIPE_READMODE_MESSAGE, n;
    char buf[256];
    int i;

    Sleep(CONNECT_DELAY_MS);
    start = GetTickCount();
    while (GetTickCount() - start < 20000) {
        h = CreateFileA(pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() == ERROR_PIPE_BUSY) WaitNamedPipeA(pipe, 1000);
        else Sleep(200);
    }
    if (h == INVALID_HANDLE_VALUE) {
        printf("child: connect failed (%lu)\n", GetLastError());
        return 1;
    }
    SetNamedPipeHandleState(h, &mode, NULL, NULL);
    printf("child: connected to %s\n", pipe);

    start = GetTickCount();
    for (i = 1; GetTickCount() - start < RUNTIME_MS - CONNECT_DELAY_MS; i++) {
        int len = snprintf(buf, sizeof buf, "beacon %d", i);
        if (!WriteFile(h, buf, (DWORD)len, &n, NULL)) break;
        if (!ReadFile(h, buf, sizeof buf - 1, &n, NULL)) break;
        buf[n] = 0;
        printf("child: got '%s'\n", buf);
        Sleep(INTERVAL_MS);
    }
    CloseHandle(h);
    printf("child: done\n");
    return 0;
}

static int run_parent(const char *self) {
    char pipe[128], cmd[MAX_PATH + 200], buf[256];
    HANDLE h;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD n, start;
    int i;

    srand(GetTickCount() ^ GetCurrentProcessId());
    snprintf(pipe, sizeof pipe, "\\\\.\\pipe\\msagent_%04x%02x", rand() & 0xffff, rand() & 0xff);

    h = CreateNamedPipeA(pipe, PIPE_ACCESS_DUPLEX,
                         PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                         PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("parent: CreateNamedPipe failed (%lu)\n", GetLastError());
        return 1;
    }
    printf("parent: created %s\n", pipe);

    snprintf(cmd, sizeof cmd, "\"%s\" child %s", self, pipe);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("parent: CreateProcess failed (%lu)\n", GetLastError());
        return 1;
    }
    CloseHandle(pi.hThread);

    if (!ConnectNamedPipe(h, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("parent: ConnectNamedPipe failed (%lu)\n", GetLastError());
        return 1;
    }
    printf("parent: client connected\n");

    start = GetTickCount();
    for (i = 1; GetTickCount() - start < RUNTIME_MS; i++) {
        int len;
        if (!ReadFile(h, buf, sizeof buf - 1, &n, NULL)) break;
        buf[n] = 0;
        printf("parent: got '%s'\n", buf);
        len = snprintf(buf, sizeof buf, "task %d", i);
        if (!WriteFile(h, buf, (DWORD)len, &n, NULL)) break;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(h);
    printf("parent: done\n");
    return 0;
}

int main(int argc, char **argv) {
    char self[MAX_PATH];
    CreateThread(NULL, 0, watchdog, NULL, 0, NULL);
    if (argc >= 3 && strcmp(argv[1], "child") == 0)
        return run_child(argv[2]);
    GetModuleFileNameA(NULL, self, sizeof self);
    return run_parent(self);
}
