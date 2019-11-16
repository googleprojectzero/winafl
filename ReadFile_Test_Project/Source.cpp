/*
THIS IS AN EXAMPLE PROGRAM TO EXPLAIN CONCEPTS RELATED TO WINAFL FUZZER
There is an concept image file which has following structure:
First 4 bytes -> header of the image file, should aways be IMG\0
then 4 bytes -> width of image file.
then 4 bytes -> height of image file.
then 10 bytes -> data of image.

There are two intentionaly kept vulnerable conditions in this code inside processimage function:
memcpy(buff, input.data, sizeof(input.data)); //condition1 -> program tries to copy data to unallocated buffer
int size2 = input.width / input.height; //condition2 -> division by 0.

users are requested to go through this program and understand the working and vulnerable condition.
WinAFL can find this issue within few minutes. you can compare the queue and crash files to see
what modificiations WinAFL has done to understand the mutations.
Author(C): Hardik Shah
Email: hardik05@gmail.com

THESE ARE BASED ON REAL LIFE VULNERBILITIES IN THE SOFTWARE AND ARE TRIMMED DOWN TO EXPLAIN THE CONCEPTS:)

command to fuzz this file(change the path to dynamorio):
copy image.img file to inputdir folder.

afl-run.exe -i inputdir -o outputdir -t 5000+ -D c:\dynamorio\bin32 -- -coverage_module readfile.exe 
-coverage_module kernel32.dll -call_convention thiscall -nargs 2 -- readfile @@

*/

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <afx.h>
#include <afxdao.h>

// structure of image file.
struct Image
{
	char header[4] = "IMG";
	int width;
	int height;
	char data[10];
};

//function responsible to parse image file.
int ProcessImage(TCHAR* name)
{
	FILE *infile;
	struct Image input;

	// Open image file for reading 
	infile = fopen(name, "r");
	if (infile == NULL)
	{
		fprintf(stderr, "\nError opening file\n");
		exit(1);
	}

	// read file header 
	fread(&input, sizeof(struct Image), 1, infile);
	fclose(infile);
	printf("width = %d height = %d\n", input.width, input.height);
	//calculate the buffer size for malloc
	int size1 = input.width * input.height;
	//allocate buffer, there is no check if it fails.
	char *buff = (char*)malloc(size1);
	//copy the data to the buffer
	memcpy(buff, input.data, sizeof(input.data)); //condition1
	int size2 = input.width / input.height; //condition2
	return 0;
}

// main program 
int _tmain(int argc, TCHAR* argv[])
{
	if (argc < 2) {
		printf("-----------------------------------------\r\n");
		printf("Vulnerable Image Reader for WinAFL\r\n");
		printf("Author: Hardik Shah, hardik05@gmail.com\r\n");
		printf("http://hardik05.wordpress.com\r\n");
		printf("twitter:https://twitter.com/hardik05")
		printf("-----------------------------------------\r\n");

		printf("Usage: %s <image file>\r\n", (char *)argv[0]);
		return 0;
	}
	ProcessImage(argv[1]);
}
