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
 * For UDP
 * set AFL_CUSTOM_DLL_ARGS=-U -p 7714 -a 127.0.0.1 -w 1000
 * For TCP
 * set AFL_CUSTOM_DLL_ARGS=-T -p 7714 -a 127.0.0.1 -w 1000
 * C:\Users\max\Desktop\winafl\winafl_fork\build\Debug>afl-fuzz.exe -l custom_net_fuzzer.dll
 * -i in -o out -D ..\..\dr_release\bin32 -t 20000 -- -target_module test_netmode.exe -target_method
 * recv_func -coverage_module test_netmode.exe -fuzz_iterations 5000 -nargs 3 -- test_netmode.exe -T 7714
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib,"ws2_32.lib") //Winsock Library

#define DEFAULT_PORT 7714
#define BUFSIZE 4096

void usage()
{
	printf("Options:\n\n"\
		"  -U            - Use UDP\n"\
		"  -T            - Use TCP\n"\
		"  7714          - Port\n");
}

void error(const char* msg)
{
	printf("[ERROR] %s %d\n", msg, WSAGetLastError());
	exit(-1);
}

int make_upd_sock(int portno)
{
	int sockfd = INVALID_SOCKET;

	while (true) {
		sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sockfd == INVALID_SOCKET) {
			error("UDP socket creation failed");
			break;
		}

		int optval = 1;
		/* UDP */
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(int))) {
			error("Set socket options failed");
			closesocket(sockfd);
			sockfd = INVALID_SOCKET;
			break;
		}

		struct sockaddr_in serveraddr;

		memset((char*)&serveraddr, 0, sizeof(serveraddr));
		serveraddr.sin_family = AF_INET;
		serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
		serveraddr.sin_port = htons((unsigned short)portno);

		if (bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) == SOCKET_ERROR) {
			error("ERROR on binding");
			closesocket(sockfd);
			sockfd = INVALID_SOCKET;
		}

		break;
	}

	return sockfd;
}

int make_tcp_sock(int portno)
{
	int clientSockFd = INVALID_SOCKET;
	int serverSockfd = INVALID_SOCKET;

	while (true) {
		// Create server socket
		serverSockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (serverSockfd == INVALID_SOCKET) {
			error("TCP socket creation failed");
		}

		struct sockaddr_in serveraddr;

		// Bind socket to port
		serveraddr.sin_family = AF_INET;
		serveraddr.sin_addr.s_addr = INADDR_ANY;
		serveraddr.sin_port = htons((unsigned short)portno);

		if (bind(serverSockfd, (sockaddr*)&serveraddr, sizeof(serveraddr)) == SOCKET_ERROR) {
			error("ERROR on binding");
		}

		// Start listening
		if (listen(serverSockfd, SOMAXCONN) == SOCKET_ERROR) {
			error("Listen failed");
		}

		//move to make_tcp_sock
		struct sockaddr_in clientAddr;
		int clientAddrSize = sizeof(clientAddr);

		clientSockFd = accept(serverSockfd, (sockaddr*)&clientAddr, &clientAddrSize);
		if (clientSockFd == INVALID_SOCKET) {
			error("connect_tcp_client err");
		}

		break;
	}

	closesocket(serverSockfd);

	return clientSockFd;
}

bool __declspec(noinline) recv_func(int sockfd)
{
	char buf[BUFSIZE] = { 0x00 };

	int	n = recv(sockfd, buf, BUFSIZE, 0);

	if (n <= 0) {
		printf("ERROR in recvfrom %d\n", WSAGetLastError());
		return false;
	}

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
	return true;
}

int main(int argc, char** argv)
{
	int sockFd;
	int portno = DEFAULT_PORT;
	static WSADATA wsaData;
	static int iResult;

	if (argc < 3) {
		usage();
		return 0;
	}

	bool useTCP = true;

	if (strcmp(argv[1], "-U") == 0x0)
		useTCP = false;

	portno = atoi(argv[2]);
	if (!portno) {
		usage();
		return 0;
	}

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (useTCP)
		sockFd = make_tcp_sock(portno);
	else
		sockFd = make_upd_sock(portno);

	if (sockFd == INVALID_SOCKET) {
		error("ERROR opening socket");
		WSACleanup();
		return -1;
	}

	while (1) {
		recv_func(sockFd);
	}

	return 0;
}
