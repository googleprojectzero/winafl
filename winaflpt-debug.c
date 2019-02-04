#include <stdio.h>
#include <stdbool.h>
#include <direct.h>
#include "windows.h"

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"

#include "winaflpt.h"

u8 *trace_bits;

u8 sinkhole_stds = 0;
u64 mem_limit = 0;
u64 cpu_aff = 0;

// todo the below functions are copied from afl-fuzz.c
// they should be taken out to a separate file to avoid duplication

u64 get_cur_time(void) {

	u64 ret;
	FILETIME filetime;
	GetSystemTimeAsFileTime(&filetime);

	ret = (((u64)filetime.dwHighDateTime) << 32) + (u64)filetime.dwLowDateTime;

	return ret / 10000;

}

//quoting on Windows is weird
size_t ArgvQuote(char *in, char *out) {
	int needs_quoting = 0;
	size_t size = 0;
	char *p = in;
	size_t i;

	//check if quoting is necessary
	if (strchr(in, ' ')) needs_quoting = 1;
	if (strchr(in, '\"')) needs_quoting = 1;
	if (strchr(in, '\t')) needs_quoting = 1;
	if (strchr(in, '\n')) needs_quoting = 1;
	if (strchr(in, '\v')) needs_quoting = 1;
	if (!needs_quoting) {
		size = strlen(in);
		if (out) memcpy(out, in, size);
		return size;
	}

	if (out) out[size] = '\"';
	size++;

	while (*p) {
		size_t num_backslashes = 0;
		while ((*p) && (*p == '\\')) {
			p++;
			num_backslashes++;
		}

		if (*p == 0) {
			for (i = 0; i < (num_backslashes * 2); i++) {
				if (out) out[size] = '\\';
				size++;
			}
			break;
		}
		else if (*p == '\"') {
			for (i = 0; i < (num_backslashes * 2 + 1); i++) {
				if (out) out[size] = '\\';
				size++;
			}
			if (out) out[size] = *p;
			size++;
		}
		else {
			for (i = 0; i < num_backslashes; i++) {
				if (out) out[size] = '\\';
				size++;
			}
			if (out) out[size] = *p;
			size++;
		}

		p++;
	}

	if (out) out[size] = '\"';
	size++;

	return size;
}


char *argv_to_cmd(char** argv) {
	u32 len = 0, i;
	u8* buf, *ret;

	//todo shell-escape

	for (i = 0; argv[i]; i++)
		len += ArgvQuote(argv[i], NULL) + 1;

	if (!len) FATAL("Error creating command line");

	buf = ret = ck_alloc(len);

	for (i = 0; argv[i]; i++) {

		u32 l = ArgvQuote(argv[i], buf);

		buf += l;

		*(buf++) = ' ';
	}

	ret[len - 1] = 0;

	return ret;
}


int main(int argc, char **argv)
{
	_mkdir(".\\ptmodules");
	int target_opt_ind = pt_init(argc, argv, ".\\ptmodules");
	if (!target_opt_ind) {
		printf("Usage: %s <instrumentation-options> -- <target command line>\n", argv[0]);
		return 0;
	}

	debug_target_pt(argv + target_opt_ind + 1);

	return 0;
}
