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

using namespace Gdiplus;

wchar_t* charToWChar(const char* text)
{
    size_t size = strlen(text) + 1;
    wchar_t* wa = new wchar_t[size];
    mbstowcs(wa,text,size);
    return wa;
}

int main(int argc, char** argv)
{
	if(argc < 2) {
		printf("Usage: %s <image file>\n", argv[0]);
		return 0;
	}

	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	Image *image = NULL;
	//*thumbnail=NULL;

	image = new Image(charToWChar(argv[1]));
	if(image && (Ok == image->GetLastStatus())) {
		//printf("Image loaded\n");
		/*thumbnail = image->GetThumbnailImage(100, 100, NULL, NULL);
		if(thumbnail && (Ok == thumbnail->GetLastStatus())) {
			//printf("Thumbnail created\n");
		}*/
	}

	//printf("Done\n");

	if(image) delete image;
	//if(thumbnail) delete thumbnail;

	GdiplusShutdown(gdiplusToken);

	return 0;
}

