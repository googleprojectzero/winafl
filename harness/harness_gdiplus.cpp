// WinAFL GDI+ Image Parser Harness
// Build:
//   cl.exe /nologo /W3 /O2 /EHsc harness\harness_gdiplus.cpp /link gdiplus.lib /OUT:harness.exe
// Fuzz:
//   build64\bin\Release\afl-fuzz.exe -i in -o out -D "d:\hacking\tools\DynamoRIO-Windows-11.3.0-1\bin64"
//     -t 5000 -- -coverage_module gdiplus.dll -target_module harness.exe
//     -target_method fuzz_target -fuzz_iterations 5000 -nargs 2 -- harness.exe @@

// Correct include order — objidl.h MUST come before gdiplus.h
#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

static ULONG_PTR g_token;

// GDI+ lifetime: initialized once per process, WinAFL loops fuzz_target not main
static void gdip_init() {
    if (!g_token) {
        GdiplusStartupInput si;
        GdiplusStartup(&g_token, &si, NULL);
    }
}

extern "C" __declspec(dllexport) int fuzz_target(int argc, char** argv) {
    if (argc < 2) return 1;

    // argv[1] is the mutated input file path
    int n = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, NULL, 0);
    WCHAR* wp = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR));
    if (!wp) return 1;
    MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wp, n);

    // Parse the image — target for fuzzing
    Bitmap* bmp = new Bitmap(wp);
    if (bmp) {
        if (bmp->GetLastStatus() == Ok) {
            // Force full decode: read pixel data
            UINT w = bmp->GetWidth(), h = bmp->GetHeight();
            if (w > 0 && h > 0) {
                BitmapData bd;
                Rect r(0, 0, (INT)w, (INT)h);
                if (bmp->LockBits(&r, ImageLockModeRead, PixelFormat32bppARGB, &bd) == Ok)
                    bmp->UnlockBits(&bd);
            }
        }
        delete bmp;
    }

    HeapFree(GetProcessHeap(), 0, wp);
    return 0;
}

int main(int argc, char** argv) {
    gdip_init();
    return fuzz_target(argc, argv);
}
