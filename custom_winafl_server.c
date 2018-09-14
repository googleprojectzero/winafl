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

#include "custom_winafl_server.h"

static SOCKET ListenSocket = INVALID_SOCKET;
static SOCKET ClientSocket = INVALID_SOCKET;

#define DEFAULT_BUFLEN 4096

//#define DEBUG_SERVER 1

/* open data and send it back into TCP/UDP socket (winAFL is a server) */
static int send_response(char *buf, long fsize, SOCKET ClientSocket) {
	/* send our test case */
#ifdef DEBUG_SERVER
    printf("Sending %s\n", buf);
#endif
    int iSendResult = send(ClientSocket, buf, fsize, 0);
	if (iSendResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();
		ExitProcess(-1);
		return 0;
	}
#ifdef DEBUG_SERVER
	printf("Bytes sent: %d\n", iSendResult);
#endif

	return 1;
}

static int recv_loop(SOCKET ClientSocket) {
	int iResult;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;

	do {
		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {
#ifdef DEBUG_SERVER
			printf("Bytes received: %d\n", iResult);
#endif
		}
		else if (iResult == 0) {
#ifdef DEBUG_SERVER
			printf("Connection closing...\n");
#endif
		}
		else {
			printf("recv failed with error: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			ExitProcess(-1);
			return 0;
		}
	} while (iResult > 0);
	return 1;
}

#define DEFAULT_BUFLEN 4096

typedef struct _test_case_struct {
	long size;
	char *data;
} test_case_struct;

/* server-mode routings */
DWORD WINAPI handle_incoming_connection(LPVOID lpParam) {
	static int iResult;
	test_case_struct *test_case = (test_case_struct *)lpParam;

#ifdef DEBUG_SERVER
	printf("Handling incoming connections\n");
#endif

	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		ExitProcess(-1);
		return 0;
	}

	recv_loop(ClientSocket);

	/* answer with test case to our client */
	int res = send_response(test_case->data, test_case->size, ClientSocket);

	if (!res) {
		printf("Failed to send response");
		ExitProcess(-1);
		return 0;
	}

	// shutdown the connection since we're done
	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();
		ExitProcess(-1);
		return 0;
	}
	free(test_case->data);
	free(test_case);
	return 1;
}

HANDLE hr = NULL;

CUSTOM_SERVER_API int APIENTRY dll_run(char *data, long size, int fuzz_iterations) {
	DWORD dwThreadId;
	test_case_struct *test_case = (test_case_struct *)malloc(sizeof(test_case_struct));
	test_case->data = (char *)malloc(size);

	memcpy(test_case->data, data, size);
	test_case->size = size;

	/* we have to create a second thread to avoid blocking winAFL in recv */
	if (hr != NULL)
		WaitForSingleObject(hr, INFINITE); /* we have to wait our previous thread to finish exec */
	hr = CreateThread(NULL, 0, handle_incoming_connection, (LPVOID)test_case, 0, &dwThreadId);
	if (hr == NULL)
		return 0;

	return 1;
}

void usage() {
	printf("Please setup AFL_CUSTOM_DLL_ARGS=<port_number>\n");
	exit(1);
}

/* winAFL is a TCP server now (TODO: implement UDP server) */
CUSTOM_SERVER_API int APIENTRY dll_init() {
	static WSADATA wsaData;
	static int iResult;
    s32 opt;
	static struct addrinfo *result = NULL;
	static struct addrinfo hints;
	static int iSendResult;

	static int first_time = 0x1;
    unsigned char *server_bind_port = NULL;

	if (!first_time)
		return 1;

    server_bind_port = getenv("AFL_CUSTOM_DLL_ARGS");
    if (server_bind_port == NULL)
        usage();

	printf("Initializing custom winAFL server\n");

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 0;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, server_bind_port, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 0;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 0;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 0;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		ExitProcess(-1);
		return 0;
	}

	printf("WinAFL server is listening on port %s\n", server_bind_port);
	first_time = 0x0;

	return 1;
}