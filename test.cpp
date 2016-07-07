/*
   WinAFL - A simple test binary that crashes on input == 'test'
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


#include <stdio.h>
#include <windows.h>

int main(int argc, char** argv)
{
	char *crash = NULL;

	if(argc < 2) {
		printf("Usage: %s <input file>\n", argv[0]);
		return 0;
	}

	FILE *fp = fopen(argv[1], "rb");
	char c;
	if(!fp) {
		printf("Error opening file\n");
		return 0;
	}
	if(fread(&c, 1, 1, fp) != 1) {
		printf("Error reading file\n");
   	    fclose(fp);
		return 0;
	}
	if(c != 't') {
		printf("Error 1\n");
   	    fclose(fp);
		return 0;
	}
	if(fread(&c, 1, 1, fp) != 1) {
		printf("Error reading file\n");
   	    fclose(fp);
		return 0;
	}
	if(c != 'e') {
		printf("Error 2\n");
   	    fclose(fp);
		return 0;
	}
	if(fread(&c, 1, 1, fp) != 1) {
		printf("Error reading file\n");
   	    fclose(fp);
		return 0;
	}
	if(c != 's') {
		printf("Error 3\n");
   	    fclose(fp);
		return 0;
	}
	if(fread(&c, 1, 1, fp) != 1) {
		printf("Error reading file\n");
   	    fclose(fp);
		return 0;
	}
	if(c != 't') {
		printf("Error 4\n");
   	    fclose(fp);
		return 0;
	}
	printf("!!!!!!!!!!OK!!!!!!!!!!\n");

	//cause a crash
	crash[0] = 1;

    fclose(fp);
	return 0;
}

