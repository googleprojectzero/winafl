/*
   WinAFL - GDI+ test binary (image parsing)
   -----------------------------------------

   Written and maintained by Ivan Fratric <ifratric@google.com>

   Copyright 2016 Google Inc. All Rights Reserved.

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

#include <stdio.h>
#include <windows.h>
#include <gdiplus.h>
#include<shlwapi.h>
#include <inttypes.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "shlwapi.lib")
using namespace Gdiplus;

/* for shared memory fuzzing */
#define MAX_SAMPLE_SIZE 1000000
#define SHM_SIZE (4 + MAX_SAMPLE_SIZE)
unsigned char* shm_data;

bool use_shared_memory;

HANDLE map_file;

//clear shared memory
int clear_shmem(void) {
	UnmapViewOfFile(shm_data);
	CloseHandle(map_file);
	return 0;
}

//setup shared memory
int setup_shmem(const char* name) {
	map_file = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,   // read/write access
		FALSE,                 // do not inherit the name
		name);            // name of mapping object

	if (map_file == NULL) {
		printf("Error accessing shared memory\n");
		return 0;
	}

	shm_data = (unsigned char*)MapViewOfFile(map_file, // handle to map object
		FILE_MAP_ALL_ACCESS,  // read/write permission
		0,
		0,
		SHM_SIZE);

	if (shm_data == NULL) {
		printf("Error accessing shared memory\n");
		return 0;
	}
	CloseHandle(map_file);
	return 1;
}

/* end shared memory fuzzing */

#define FUZZ_TARGET_MODIFIERS __declspec(dllexport)

wchar_t* charToWChar(const char* text)
{
	size_t size = strlen(text) + 1;
	wchar_t* wa = new wchar_t[size];
	mbstowcs(wa, text, size);
	return wa;
}

int FUZZ_TARGET_MODIFIERS FuzzMe(wchar_t* filename)
{
	Image* image = NULL;
	Image* thumbnail = NULL;
	if (!use_shared_memory)
	{
		image = new Image(filename);
	}
	else
	{
		char* sample_bytes = NULL;
		uint32_t sample_size = 0;
		sample_size = *(uint32_t*)(shm_data);
		if (sample_size > MAX_SAMPLE_SIZE) sample_size = MAX_SAMPLE_SIZE;
		sample_bytes = (char*)malloc(sample_size);
		memcpy(sample_bytes, shm_data + sizeof(uint32_t), sample_size);
		//lets create stream from memory and then we will create image.
		IStream* stream = SHCreateMemStream(reinterpret_cast<BYTE*>(sample_bytes), sample_size);
		image = Gdiplus::Image::FromStream(stream);
	}
		if (image && (Ok == image->GetLastStatus())) {
			//printf("Image loaded\n");
			//thumbnail = image->GetThumbnailImage(100, 100, NULL, NULL);
			if (thumbnail && (Ok == thumbnail->GetLastStatus())) {
				//printf("Thumbnail created\n");
			}
		}
	
	//printf("Done\n");

	if (image) delete image;
	if (thumbnail) delete thumbnail;	
	return 0;

}

int main(int argc, char** argv)
{
	wchar_t* filename;

	printf("[+] %s() offset: 0x%x\n", __FUNCTION__, (char*)(*&FuzzMe) - (char*)GetModuleHandleW(NULL));
	if (argc < 3) {
		printf("Usage: %s <-f|-m> <image file|shared memory>\n", argv[0]);
		return 0;
	}

	if (!strcmp(argv[1], "-m")) {
		use_shared_memory = true;
	}
	else if (!strcmp(argv[1], "-f")) {
		use_shared_memory = false;
	}
	else {
		printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
		return 0;
	}

	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
	filename = charToWChar(argv[2]);

	if (use_shared_memory) {
		if (!setup_shmem(argv[2])) {
			printf("Error mapping shared memory\n");
		}
	}

	FuzzMe(filename);	
	clear_shmem();
	GdiplusShutdown(gdiplusToken);
	return 0;
}
