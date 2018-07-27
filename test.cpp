/*
   WinAFL - A simple test binary that crashes on certain inputs:
     - 'test1' with a normal write access violation at NULL
     - 'test2' with a /GS stack cookie violation
   -------------------------------------------------------------

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

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <string.h>


int __declspec(noinline) test_target(char* input_file_path, char* argv_0)
{
	char *crash = NULL;
	FILE *fp = fopen(input_file_path, "rb");
	char c;
	if (!fp) {
		printf("Error opening file\n");
		return 0;
	}
	if (fread(&c, 1, 1, fp) != 1) {
		printf("Error reading file\n");
		fclose(fp);
		return 0;
	}
	if (c != 't') {
		printf("Error 1\n");
		fclose(fp);
		return 0;
	}
	if (fread(&c, 1, 1, fp) != 1) {
		printf("Error reading file\n");
		fclose(fp);
		return 0;
	}
	if (c != 'e') {
		printf("Error 2\n");
		fclose(fp);
		return 0;
	}
	if (fread(&c, 1, 1, fp) != 1) {
		printf("Error reading file\n");
		fclose(fp);
		return 0;
	}
	if (c != 's') {
		printf("Error 3\n");
		fclose(fp);
		return 0;
	}
	if (fread(&c, 1, 1, fp) != 1) {
		printf("Error reading file\n");
		fclose(fp);
		return 0;
	}
	if (c != 't') {
		printf("Error 4\n");
		fclose(fp);
		return 0;
	}
	printf("!!!!!!!!!!OK!!!!!!!!!!\n");

	if (fread(&c, 1, 1, fp) != 1) {
		printf("Error reading file\n");
		fclose(fp);
		return 0;
	}
	if (c == '1') {
		// cause a crash
		crash[0] = 1;
	}
	else if (c == '2') {
		char buffer[5] = { 0 };
		// stack-based overflow to trigger the GS cookie corruption
		for (int i = 0; i < 5; ++i)
			strcat(buffer, argv_0);
		printf("buffer: %s\n", buffer);
	}
	else {
		printf("Error 5\n");
	}
	fclose(fp);
	return 0;
}

int main(int argc, char** argv)
{
    if(argc < 2) {
        printf("Usage: %s <input file>\n", argv[0]);
        return 0;
    }

	if (argc == 3 && !strcmp(argv[2], "loop"))
	{
		//loop inside application and call target infinitey
		while (true)
		{
			test_target(argv[1], argv[0]);
		}
	}
	else
	{
		//regular single target call
		return test_target(argv[1], argv[0]);
	}
}
