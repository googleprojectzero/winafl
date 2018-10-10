/*
custom_net_fuzzer - a shared DLL to enable network fuzzing in winAFL
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

static u8  enable_socket_fuzzing = 0; /* Enable network fuzzing           */
static u8  is_TCP = 1;                /* TCP or UDP                       */
static u32 target_port = 0x0;         /* Target port to send test cases   */
static u32 socket_init_delay = SOCKET_INIT_DELAY; /* Socket init delay    */
static u8 *target_ip_address = NULL;  /* Target IP to send test cases     */


static SOCKET ListenSocket = INVALID_SOCKET;
static SOCKET ClientSocket = INVALID_SOCKET;

static void send_data_tcp(const char *buf, const int buf_len, int first_time) {
    static struct sockaddr_in si_other;
    static int slen = sizeof(si_other);
    static WSADATA wsa;
    int s;

    if (first_time == 0x0) {
        /* wait while the target process open the socket */
        Sleep(socket_init_delay);

        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            FATAL("WSAStartup failed. Error Code : %d", WSAGetLastError());

        // setup address structure
        memset((char *)&si_other, 0, sizeof(si_other));
        si_other.sin_family = AF_INET;
        si_other.sin_port = htons(target_port);
        si_other.sin_addr.S_un.S_addr = inet_addr((char *)target_ip_address);
    }

    /* In case of TCP we need to open a socket each time we want to establish
    * connection. In theory we can keep connections always open but it might
    * cause our target behave differently (probably there are a bunch of
    * applications where we should apply such scheme to trigger interesting
    * behavior).
    */
    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == SOCKET_ERROR)
        FATAL("socket() failed with error code : %d", WSAGetLastError());

    // Connect to server.
    if (connect(s, (SOCKADDR *)& si_other, slen) == SOCKET_ERROR)
        FATAL("connect() failed with error code : %d", WSAGetLastError());

    // Send our buffer
    if (send(s, buf, buf_len, 0) == SOCKET_ERROR)
        FATAL("send() failed with error code : %d", WSAGetLastError());

    // shutdown the connection since no more data will be sent
    if (shutdown(s, 0x1/*SD_SEND*/) == SOCKET_ERROR)
        FATAL("shutdown failed with error: %d\n", WSAGetLastError());
    // close the socket to avoid consuming much resources
    if (closesocket(s) == SOCKET_ERROR)
        FATAL("closesocket failed with error: %d\n", WSAGetLastError());
}

static void send_data_udp(const char *buf, const int buf_len, int first_time) {
    static struct sockaddr_in si_other;
    static int s, slen = sizeof(si_other);
    static WSADATA wsa;

    if (first_time == 0x0) {
        /* wait while the target process open the socket */
        Sleep(socket_init_delay);

        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            FATAL("WSAStartup failed. Error Code : %d", WSAGetLastError());

        if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
            FATAL("socket() failed with error code : %d", WSAGetLastError());

        // setup address structure
        memset((char *)&si_other, 0, sizeof(si_other));
        si_other.sin_family = AF_INET;
        si_other.sin_port = htons(target_port);
        si_other.sin_addr.S_un.S_addr = inet_addr((char *)target_ip_address);
    }

    // send the data
    if (sendto(s, buf, buf_len, 0, (struct sockaddr *) &si_other, slen) == SOCKET_ERROR)
        FATAL("sendto() failed with error code : %d", WSAGetLastError());
}

#define DEFAULT_BUFLEN 4096

CUSTOM_SERVER_API int APIENTRY dll_run(char *data, long size, int fuzz_iterations) {
    if (is_TCP)
        send_data_tcp(data, size, fuzz_iterations);
    else
        send_data_udp(data, size, fuzz_iterations);
    return 1;
}

static int optind;
static u8 *optarg;

int getopt(int argc, char **argv, char *optstring) {
    char *c;
    optarg = NULL;
    int i = 0;

    while (1) {
        if (optind == argc) return -1;

        if (argv[optind][0] != '-') {
            optind++;
            continue;
        }
        if (!argv[optind][1]) {
            optind++;
            continue;
        }

        c = strchr(optstring, argv[optind][1]);
        if (!c) {
            optind++;
            continue;
        }

        optind++;
        if (c[1] == ':') {
            if (optind == argc) return -1;
            optarg = argv[optind];
            optind++;
        }

        return (int)(c[0]);
    }
}

void usage() {
    printf("Network fuzzing options:\n\n"\
    "  -a            - IP address to send data in\n"\
    "  -U            - Use UDP (default TCP)\n"\
    "  -p            - Port to send data in\n"\
    "  -w            - Delay in milliseconds before start sending data\n");
    exit(1);
}
static int optind;
static u8 *optarg;

#define MAX_ARGS 28

char **convert_to_array(char *args, int *argc) {
    int element_id = 0;
    int last_element_offset = 0;
    char *c = NULL;

    int length = strlen(args);
    char **argv = malloc(MAX_ARGS * sizeof (char *));

    while (args) {
        c = strchr(args, ' ');
        if (!c)
            break;

        int len = c - args;
        if (len <= 0)
            break;

        char *element = malloc(len);
        memcpy(element, args, len);
        element[len] = '\0';

        argv[element_id] = element;

        element_id++;
        if (element_id >= MAX_ARGS) {
            usage();
            break;
        }

        args = c + 1;
    }
    argv[element_id] = strdup(args);

    *argc = element_id + 1;
    return argv;
}

CUSTOM_SERVER_API int APIENTRY dll_init() {
    s32 opt;
    static int iSendResult;
    static int first_time = 0x1;
    int argc;

    if (!first_time)
        return 1;

    char *args = getenv("AFL_CUSTOM_DLL_ARGS");

    char **argv = convert_to_array(args, &argc);

    if (args == NULL)
        usage();

    while ((opt = getopt(argc, argv, "Ua:p:w:")) > 0) {
        switch (opt) {
        case 'a':
            target_ip_address = ck_strdup(optarg);

            break;

        case 'U':
            is_TCP = 0;

            break;

        case 'p':
            if (sscanf(optarg, "%u", &target_port) < 1 ||
                optarg[0] == '-') FATAL("Bad syntax used for -p");

            break;

        case 'w':
            if (sscanf(optarg, "%u", &socket_init_delay) < 1 ||
                optarg[0] == '-') FATAL("Bad syntax used for -w");

            break;
        default:
            break;
        }
    }

    if (target_ip_address == NULL || target_port == 0)
        usage();

    printf("Ready to begin fuzzing. Target IP= %s, target port = %d\n",
           target_ip_address, target_port);
    first_time = 0x0;
    return 1;
}
