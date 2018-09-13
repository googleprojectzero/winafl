/*
custom_winafl_server - a shared DLL to enable server-mode fuzzing in winAFL:
-------------------------------------------------------------

Written and maintained by Maksim Shudrak <mxmssh@gmail.com>

Copyright 2018 Salesforce Inc. All Rights Reserved.

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

#pragma once

#define WIN32_LEAN_AND_MEAN /* prevent winsock.h to be included in windows.h */

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <wininet.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdlib.h>

#include <winsock2.h>
#include <ws2tcpip.h>


#pragma comment(lib,"ws2_32.lib") //Winsock Library
#pragma comment( lib, "wininet")

#include "alloc-inl.h"

#define CUSTOM_SERVER_API __declspec(dllexport)

CUSTOM_SERVER_API int APIENTRY dll_init();
CUSTOM_SERVER_API int APIENTRY dll_run(char *data, long size, int fuzz_iterations);

/* Default delay in milliseconds to let the target open a socket and start listen for
 * incoming packages.
*/
#define SOCKET_INIT_DELAY 30000