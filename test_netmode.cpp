/*
   WinAFL - A simple binary to test winAFL ability perform fuzzing over network:
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

/* cmd line to find the crash:
 * set AFL_CUSTOM_DLL_ARGS=-U -p 7714 -a 127.0.0.1 -w 1000
 * C:\Users\max\Desktop\winafl\winafl_fork\build\Debug>afl-fuzz.exe -l custom_net_fuzzer.dll 
 * -i in -o out -D ..\..\dr_release\bin32 -t 20000 -- -target_module test_netmode.exe -target_method 
 * recv_func -coverage_module test_netmode.exe -fuzz_iterations 5000 -nargs 1 -- test_netmode.exe
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

#define DEFAULT_PORT 7714
#define BUFSIZE 4096

/* TODO: test for TCP */

void error(const char *msg) {
	printf("[ERROR] %s %d\n", msg, WSAGetLastError());
    exit(-1);
}

struct sockaddr_in serveraddr;	  /* server's addr */

void recv_func(int sockfd)
{	
    char *buf;
	struct sockaddr_in clientaddr;	  /* client addr */
	int clientlen = sizeof(clientaddr);
    int n = 0;

    buf = (char *)malloc(BUFSIZE);

    /* receiving over UDP */
    n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &clientlen);
    if (n < 0)
        error("ERROR in recvfrom");

    if (buf[0] == 'P') {
		if (buf[1] == 'W') {
			if (buf[2] == 'N') {
				if (buf[3] == 'I') {
					if (buf[4] == 'T') {
						printf("Found it!\n");
						((VOID(*)())0x0)();
					}
				}
			}
		}
	}

    printf("Received %d bytes, content = %s\n", n, buf);
    free(buf);
}

int main(int argc, char** argv)
{
	int sockfd;
	int portno = DEFAULT_PORT;
	int optval;
	static WSADATA wsaData;
	static int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	optval = 1;
    /* UDP */
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(int));

	memset((char *)&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)portno);

	if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
		error("ERROR on binding");
	while (1) {
		recv_func(sockfd);
	}
    return 0;
}
