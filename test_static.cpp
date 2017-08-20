/*
   WinAFL - A simple test binary that exercises various behaviors
   depending on inputs:
     - 'test1' crashes with a normal write access violation at NULL
     - 'test2' crashes with a /GS stack cookie violation
     - 'test3' triggers a hang
     - 'test4' triggers an exception that is caught and handled
     - 'test5' triggers an OutputDebugString
     - 'test6' triggers an allocation of 120MB (and a crash if the
               allocation fails)
   -------------------------------------------------------------

   Written by Axel "0vercl0k" Souchet <0vercl0k@tuxfamily.org>

   Copyright 2017 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include "afl-staticinstr.h"

int test(int argc, char **argv) {
    char *crash = NULL;
    FILE *fp = fopen(argv[1], "rb");
    char c;
    if (!fp) {
        printf("Error opening file\n");
        goto end;
    }
    if (fread(&c, 1, 1, fp) != 1) {
        printf("Error reading file\n");
        goto clean;
    }
    if (c != 't') {
        printf("Error 1\n");
        goto clean;
    }
    if (fread(&c, 1, 1, fp) != 1) {
        printf("Error reading file\n");
        goto clean;
    }
    if (c != 'e') {
        printf("Error 2\n");
        goto clean;
    }
    if (fread(&c, 1, 1, fp) != 1) {
        printf("Error reading file\n");
        goto clean;
    }
    if (c != 's') {
        printf("Error 3\n");
        goto clean;
    }
    if (fread(&c, 1, 1, fp) != 1) {
        printf("Error reading file\n");
        goto clean;
    }
    if (c != 't') {
        printf("Error 4\n");
        goto clean;
    }
    printf("!!!!!!!!!!OK!!!!!!!!!!\n");

    if (fread(&c, 1, 1, fp) != 1) {
        printf("Error reading file\n");
        goto clean;
    }
    if (c == '1') {
        crash[0] = 1;
    }
    else if (c == '2') {
        char buffer[5] = { 0 };
        strcat(buffer, argv[0]);
    }
    else if (c == '3') {
        printf("triggering a hang\n");
        Sleep(50 * 1000);
    }
    else if (c == '4') {
        try {
            throw int(1337);
        }
        catch (...) {
            printf("Caught its ok!\n");
        }
    }
    else if (c == '5') {
        OutputDebugString(TEXT("hello!"));
    }
    else if (c == '6') {
        printf("allocating 120MB\n");
        char *buffer = (char*)malloc((1024 * 1024) * 120);
        *buffer = 0;
        free(buffer);
    }
    else {
        printf("Error 5\n");
    }

    clean:
    fclose(fp);

    end:
    return EXIT_SUCCESS;
}

#pragma optimize("", off)
int fuzz(int argc, char**argv) {
    while(__afl_persistent_loop()) {
        test(argc, argv);
    }
    return 1;
}
#pragma optimize("", on)

int main(int argc, char** argv)
{
    if(argc < 2) {
        printf("Usage: %s <input file>\n", argv[0]);
        return 0;
    }

    return fuzz(argc, argv);
}
