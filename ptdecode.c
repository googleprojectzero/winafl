#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "windows.h"

#include "intel-pt.h"
#include "pt_cpu.h"
#include "pt_cpuid.h"
#include "pt_opcodes.h"

#include "types.h"
#include "config.h"
#include "debug.h"

#include "winaflpt.h"
#include "ptdecode.h"

#define PPT_EXT 0xFF

uint64_t previous_offset;
uint64_t previous_ip;

extern address_range* coverage_ip_ranges;
extern size_t num_ip_ranges;

static address_range* current_range;

unsigned char opc_lut[] = {
	0x02, 0x08, 0xff, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x0f, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x11, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x0b, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x08, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x06, 0x09, 0x12,
	0x09, 0x07, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x05, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12,
	0x09, 0x00, 0x09, 0x12, 0x09, 0x00, 0x09, 0x12
};

unsigned char ext_lut[] = {
	0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x03, 0x13, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x19, 0x0a, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x17, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char opc_size_lut[] = {
	0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x08, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x03, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x03, 0x01, 0x01,
	0x01, 0x03, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x03, 0x01, 0x01,
	0x01, 0x05, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x05, 0x01, 0x01,
	0x01, 0x05, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x02, 0x01, 0x01, 0x01, 0x05, 0x01, 0x01,
	0x01, 0x07, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x07, 0x01, 0x01,
	0x01, 0x07, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x07, 0x01, 0x01,
	0x01, 0x07, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x07, 0x01, 0x01,
	0x01, 0x07, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x02, 0x01, 0x01, 0x01, 0x07, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x09, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x09, 0x01, 0x01,
	0x01, 0x09, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x09, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01,
	0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01
};

unsigned char ext_size_lut[] = {
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char psb[16] = {
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
};

void dump_lut(unsigned char *lut, char *lutname) {
	printf("unsigned char %s[] = {\n", lutname);
	for (int i = 0; i<16; i++) {
		printf("  ");
		for (int j = 0; j<16; j++) {
			printf("%02x", lut[i * 16 + j]);
			if (j != 15) printf(", ");
		}
		if (i != 15) printf(",\n");
		else printf("\n");
	}
	printf("}; \n\n");
}

void build_luts() {
	for (int i = 0; i<256; i++) {
		opc_lut[i] = ppt_invalid;
	}

	for (int i = 0; i<256; i++) {
		ext_lut[i] = ppt_invalid;
	}

	for (int i = 0; i<256; i++) {
		opc_size_lut[i] = 0;
		ext_size_lut[i] = 0;
	}

	//ext packets
	opc_lut[pt_opc_ext] = PPT_EXT;
	opc_size_lut[pt_opc_ext] = 1; // not really important

								  //pad packet
	opc_lut[pt_opc_pad] = ppt_pad;
	opc_size_lut[pt_opc_pad] = 1;

	//tip packet
	for (int i = 0; i<8; i++) {
		unsigned char opcode = (unsigned char)((i << 5) + 0xd);

		if (i == 0) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1;
		}
		else if (i == 1) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1 + 2;
		}
		else if (i == 2) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1 + 4;
		}
		else if ((i == 3) || (i == 4)) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1 + 6;
		}
		else if (i == 6) {
			opc_lut[opcode] = ppt_tip;
			opc_size_lut[opcode] = 1 + 8;
		}
	}

	//tip.pge packet
	for (int i = 0; i<8; i++) {
		unsigned char opcode = (unsigned char)((i << 5) + 0x11);

		if (i == 0) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1;
		}
		else if (i == 1) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1 + 2;
		}
		else if (i == 2) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1 + 4;
		}
		else if ((i == 3) || (i == 4)) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1 + 6;
		}
		else if (i == 6) {
			opc_lut[opcode] = ppt_tip_pge;
			opc_size_lut[opcode] = 1 + 8;
		}
	}

	//tip.pgd packet
	for (int i = 0; i<8; i++) {
		unsigned char opcode = (unsigned char)((i << 5) + 0x1);

		if (i == 0) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1;
		}
		else if (i == 1) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1 + 2;
		}
		else if (i == 2) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1 + 4;
		}
		else if ((i == 3) || (i == 4)) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1 + 6;
		}
		else if (i == 6) {
			opc_lut[opcode] = ppt_tip_pgd;
			opc_size_lut[opcode] = 1 + 8;
		}
	}

	//fup packet
	for (int i = 0; i<8; i++) {
		unsigned char opcode = (unsigned char)((i << 5) + 0x1d);

		if (i == 0) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1;
		}
		else if (i == 1) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1 + 2;
		}
		else if (i == 2) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1 + 4;
		}
		else if ((i == 3) || (i == 4)) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1 + 6;
		}
		else if (i == 6) {
			opc_lut[opcode] = ppt_fup;
			opc_size_lut[opcode] = 1 + 8;
		}
	}

	//mode packet
	opc_lut[pt_opc_mode] = ppt_mode;
	opc_size_lut[pt_opc_mode] = 2;

	//tsc packet
	opc_lut[pt_opc_tsc] = ppt_tsc;
	opc_size_lut[pt_opc_tsc] = 8;

	//mtc packet
	opc_lut[pt_opc_mtc] = ppt_mtc;
	opc_size_lut[pt_opc_mtc] = 2;

	//cyc packet
	for (int i = 0; i<64; i++) {
		unsigned char opcode = (unsigned char)((i << 2) + 0x3);
		opc_lut[opcode] = ppt_cyc;
		opc_size_lut[opcode] = 1;
	}

	//tnt packets
	for (int i = 1; i <= 6; i++) {
		for (int bits = 0; bits<(1 << i); bits++) {
			unsigned char opcode = (unsigned char)((1 << (i + 1)) + (bits << 1));
			opc_lut[opcode] = ppt_tnt_8;
			opc_size_lut[opcode] = 1;
		}
	}

	//////extensions///////

	//psb packet
	ext_lut[pt_ext_psb] = ppt_psb;
	ext_size_lut[pt_ext_psb] = 16;

	//long tnt packet
	ext_lut[pt_ext_tnt_64] = ppt_tnt_64;
	ext_size_lut[pt_ext_tnt_64] = 8;

	//pip packet
	ext_lut[pt_ext_pip] = ppt_pip;
	ext_size_lut[pt_ext_pip] = 8;

	//ovf packet
	ext_lut[pt_ext_ovf] = ppt_ovf;
	ext_size_lut[pt_ext_ovf] = 2;

	//psbend packet
	ext_lut[pt_ext_psbend] = ppt_psbend;
	ext_size_lut[pt_ext_psbend] = 2;

	//cbr packet
	ext_lut[pt_ext_cbr] = ppt_cbr;
	ext_size_lut[pt_ext_cbr] = 4;

	//tma packet
	ext_lut[pt_ext_tma] = ppt_tma;
	ext_size_lut[pt_ext_tma] = 8;

	//stop packet
	ext_lut[pt_ext_stop] = ppt_stop;
	ext_size_lut[pt_ext_stop] = 2;

	//vmcs packet
	ext_lut[pt_ext_vmcs] = ppt_vmcs;
	ext_size_lut[pt_ext_vmcs] = 8;

	//exstop packet
	ext_lut[pt_ext_exstop] = ppt_exstop;
	ext_size_lut[pt_ext_exstop] = 2;

	//exstop-ip packet
	ext_lut[pt_ext_exstop_ip] = ppt_exstop;
	ext_size_lut[pt_ext_exstop_ip] = 2;

	//mwait packet
	ext_lut[pt_ext_mwait] = ppt_mwait;
	ext_size_lut[pt_ext_mwait] = 10;

	//pwre packet
	ext_lut[pt_ext_pwre] = ppt_pwre;
	ext_size_lut[pt_ext_pwre] = 4;

	//pwrx packet
	ext_lut[pt_ext_pwrx] = ppt_pwrx;
	ext_size_lut[pt_ext_pwrx] = 8;

	//ptw packet
	for (int i = 0; i<2; i++) {
		for (int j = 0; j<2; j++) {
			unsigned char opcode = (unsigned char)((i << 7) + (j << 5) + 0x12);
			ext_lut[opcode] = ppt_ptw;
			if (j == 0) {
				ext_size_lut[opcode] = 6;
			}
			else if (j == 1) {
				ext_size_lut[opcode] = 10;
			}
		}
	}

	//ext2
	ext_lut[pt_ext_ext2] = PPT_EXT;
	ext_size_lut[pt_ext_ext2] = 1; // not really important

	dump_lut(opc_lut, "opc_lut");
	dump_lut(ext_lut, "ext_lut");
	dump_lut(opc_size_lut, "opc_size_lut");
	dump_lut(ext_size_lut, "ext_size_lut");
}

inline static uint64_t sext(uint64_t val, uint8_t sign) {
	uint64_t signbit, mask;

	signbit = 1ull << (sign - 1);
	mask = ~0ull << sign;

	return val & signbit ? val | mask : val & ~mask;
}

bool findpsb(unsigned char **data, size_t *size) {
	if (*size < 16) return false;

	if (memcmp(*data, psb, sizeof(psb)) == 0) return true;

	for (size_t i = 0; i < (*size - sizeof(psb) - 1); i++) {
		if (((*data)[i] == psb[0]) && ((*data)[i+1] == psb[1])) {
			if (memcmp((*data) + i, psb, sizeof(psb)) == 0) {
				*data = *data + i;
				*size = *size - i;
				return true;
			}
		}
	}

	return false;
}

inline static int update_coverage_map(uint64_t next_ip, u8 *trace_bits, int coverage_kind) {
	uint64_t offset;

	if (next_ip < current_range->start) {
		do {
			current_range--;
		} while (next_ip < current_range->start);
	} else if (next_ip > current_range->end) {
		do {
			current_range++;
		} while (next_ip > current_range->end);
	}

	if (!current_range->collect) return 0;

	// printf("ip: %p\n", (void*)next_ip);

	offset = next_ip - current_range->start;

	switch (coverage_kind) {
	case COVERAGE_BB:
		trace_bits[offset % MAP_SIZE]++;
		break;
	case COVERAGE_EDGE:
		trace_bits[(offset ^ previous_offset) % MAP_SIZE]++;
		previous_offset = offset >> 1;
	break;
	}

	return 1;
}

// analyze collected PT trace
void analyze_trace_buffer_full(unsigned char *trace_data, size_t trace_size, u8 *trace_bits, int coverage_kind, module_info_t* modules, struct pt_image_section_cache *section_cache) {
	// printf("analyzing trace\n");

	struct pt_block_decoder *decoder;
	struct pt_config config;
	struct pt_event event;
	struct pt_block block;

	bool skip_next = false;

	previous_offset = 0;
	previous_ip = 0;
	current_range = &(coverage_ip_ranges[0]);

	pt_config_init(&config);
	pt_cpu_read(&config.cpu);
	pt_cpu_errata(&config.errata, &config.cpu);
	config.begin = trace_data;
	config.end = trace_data + trace_size;

	// This is important not only for accurate coverage, but also because
	// if we don't set it, the decoder is sometimes going to break
	// blocks on these instructions anyway, resulting in new coverage being
	// detected where there in fact was none.
	// See also skip_next comment below
	config.flags.variant.block.end_on_call = 1;
	config.flags.variant.block.end_on_jump = 1;

	decoder = pt_blk_alloc_decoder(&config);
	if (!decoder) {
		FATAL("Error allocating decoder\n");
	}

	struct pt_image *image = pt_image_alloc("winafl_image");
	module_info_t *cur_module = modules;
	while (cur_module) {
		if (cur_module->isid > 0) {
			int ret = pt_image_add_cached(image, section_cache, cur_module->isid, NULL);
		}
		cur_module = cur_module->next;
	}
	int ret = pt_blk_set_image(decoder, image);

	int status;

	for (;;) {
		status = pt_blk_sync_forward(decoder);
		if (status < 0) {
			// printf("cant't sync\n");
			break;
		}

		for (;;) {

			// we aren't really interested in events
			// but have to empty the event queue
			while (status & pts_event_pending) {
				status = pt_blk_event(decoder, &event, sizeof(event));
				if (status < 0)
					break;

				// printf("event %d\n", event.type);
			}

			if (status < 0)
				break;

			status = pt_blk_next(decoder, &block, sizeof(block));

			if (status < 0) {
				break;
			}

			if (!skip_next) {
				skip_next = false;
				update_coverage_map(block.ip, trace_bits, coverage_kind);
				// printf("ip: %p, %d %d\n", (void *)block.ip, status, block.iclass);
			}

			// Sometimes, due to asynchronous events and other reasons (?)
			// the tracing of a basic block will break in the middle of it
			// and the subsequent basic block will continue where the previous
			// one was broken, resulting in new coverage detected where there
			// was none.
			// Currently, this is resolved by examining the instruction class of
			// the last instruction in the basic block. If it is not one of the 
			// instructions that normally terminate a basic block, we will simply
			// ignore the subsequent block.
			// Another way to do this could be to compute the address of the next
			// instruction after the basic block, and only ignore a subsequent block
			// if it starts on that address
			if(block.iclass == ptic_other) skip_next = true;
			else skip_next = false;
		}
	}

	pt_image_free(image);
	pt_blk_free_decoder(decoder);
}

static inline int get_next_opcode(unsigned char **data_p, size_t *size_p, unsigned char *opcode_p, unsigned char *opcodesize_p) {
	unsigned char *data = *data_p;
	size_t size = *size_p;

	unsigned char opcode = opc_lut[*data];
	unsigned char opcodesize = opc_size_lut[*data];
    
    // handle extensions
    if(opcode == PPT_EXT) {
      if(size < 2) return 0;

      opcode = ext_lut[*(data+1)];
      opcodesize = ext_size_lut[*(data+1)];

      // second-level extension
      if(opcode == PPT_EXT) {
        if(size < 3) return 0;
        
        // currently there is only one possibility
        if((*(data+2)) == 0x88) {
          opcode = ppt_mnt;
          opcodesize = 11;
        } else {
          opcode = ppt_invalid;
          opcodesize = 0;
        }
      }
    } else if(opcode == ppt_cyc) {
      // special handling for cyc packets since
      // they don't have a predetermined size
      if(*data & 4) {
        opcodesize = 2;

        while(1) {
          if(size < opcodesize) return 0;
          if(!((*(data + (opcodesize - 1))) & 1)) break;
          opcodesize++;
        }
      }
    }

	if (size < opcodesize) return 0;

	*opcode_p = opcode;
	*opcodesize_p = opcodesize;

	return 1;
}

static inline uint64_t decode_ip(unsigned char *data) {
	uint64_t next_ip;

	switch ((*data) >> 5) {
	case 0:
		next_ip = previous_ip;
		break;
	case 1:
		next_ip = (previous_ip & 0xFFFFFFFFFFFF0000ULL) | *((uint16_t *)(data + 1));
		break;
	case 2:
		next_ip = (previous_ip & 0xFFFFFFFF00000000ULL) | *((uint32_t *)(data + 1));
		break;
	case 3:
		next_ip = sext(*((uint32_t *)(data + 1)) | ((uint64_t)(*((uint16_t *)(data + 5))) << 32), 48);
		break;
	case 4:
		next_ip = (previous_ip & 0xFFFF000000000000ULL) | *((uint32_t *)(data + 1)) | ((uint64_t)(*((uint16_t *)(data + 5))) << 32);
		break;
	case 6:
		next_ip = *((uint64_t *)(data + 1));
		break;
	}
	previous_ip = next_ip;

	return next_ip;
}

// fast decoder that decodes only tip (and related packets)
// and skips over the reset
void decode_trace_tip_fast(unsigned char *data, size_t size, u8 *trace_bits, int coverage_kind) {
  uint64_t next_ip;

  unsigned char opcode;
  unsigned char opcodesize;

  previous_offset = 0;
  previous_ip = 0;
  current_range = &(coverage_ip_ranges[0]);

  if (size < sizeof(psb)) return;

  if (!findpsb(&data, &size)) {
	  FATAL("No sync packets in trace\n");
	  return;
  }

  while(size) {

	if (!get_next_opcode(&data, &size, &opcode, &opcodesize)) return;

    if(opcode == ppt_invalid) {
      printf("Decoding error\n");
	  if (findpsb(&data, &size)) continue;
	  else return;
    }

	// printf("packet type: %d\n", opcode);

    switch (opcode) {
    case ppt_fup:
    case ppt_tip:
    case ppt_tip_pge:
    case ppt_tip_pgd:
	  next_ip = decode_ip(data);
      break;
    default:
      break;
    }

	if (opcode == ppt_tip) {
		// printf("ip: %p\n", (void*)next_ip);
		update_coverage_map(next_ip, trace_bits, coverage_kind);
	}

    size -= opcodesize;
    data += opcodesize;
  }
}

int check_trace_start(unsigned char *data, size_t size, uint64_t expected_ip) {
	unsigned char opcode;
	unsigned char opcodesize;

	previous_ip = 0;

	while (size) {
		if (!get_next_opcode(&data, &size, &opcode, &opcodesize)) return 0;

		switch (opcode) {
		case ppt_tip_pge:
			if (decode_ip(data) == expected_ip) return 1;
			else return 0;
		case ppt_fup:
		case ppt_tip:
		case ppt_tnt_8:
		case ppt_tnt_64:
		case ppt_tip_pgd:
		case ppt_invalid:
			return 0;
		default:
			break;
		}

		size -= opcodesize;
		data += opcodesize;
	}

	return 0;
}

// process a sinle IPT packet and update AFL map
inline static void process_packet(struct pt_packet *packet, u8 *trace_bits, int coverage_kind) {
	// printf("packet type: %d\n", packet->type);

	if ((packet->type != ppt_tip) && (packet->type != ppt_tip_pge) && (packet->type != ppt_tip_pgd) && (packet->type != ppt_fup)) {
		return;
	}

	uint64_t next_ip;
	switch (packet->payload.ip.ipc) {
	case pt_ipc_update_16:
		next_ip = (previous_ip & 0xFFFFFFFFFFFF0000ULL) | (packet->payload.ip.ip & 0xFFFF);
		break;
	case pt_ipc_update_32:
		next_ip = (previous_ip & 0xFFFFFFFF00000000ULL) | (packet->payload.ip.ip & 0xFFFFFFFF);
		break;
	case pt_ipc_update_48:
		next_ip = (previous_ip & 0xFFFF000000000000ULL) | (packet->payload.ip.ip & 0xFFFFFFFFFFFF);
		break;
	case pt_ipc_sext_48:
		next_ip = sext(packet->payload.ip.ip, 48);
		break;
	case pt_ipc_full:
		next_ip = packet->payload.ip.ip;
		break;
	default:
		return;
	}

	previous_ip = next_ip;

	if (packet->type == ppt_tip) {
		// printf("ip: %p\n", (void*)next_ip);
		update_coverage_map(next_ip, trace_bits, coverage_kind);
	}
}

// analyze collected PT trace
void decode_trace_tip_reference(unsigned char *trace_data, size_t trace_size, u8 *trace_bits, int coverage_kind) {
	// printf("analyzing trace\n");

	struct pt_packet_decoder *decoder;
	struct pt_config ptc;
	struct pt_packet packet;

	previous_offset = 0;
	previous_ip = 0;
	current_range = &(coverage_ip_ranges[0]);

	pt_config_init(&ptc);
	pt_cpu_read(&ptc.cpu);
	pt_cpu_errata(&ptc.errata, &ptc.cpu);
	ptc.begin = trace_data;
	ptc.end = trace_data + trace_size;

	decoder = pt_pkt_alloc_decoder(&ptc);
	if (!decoder) {
		FATAL("Error allocating decoder\n");
	}

	for (;;) {
		if (pt_pkt_sync_forward(decoder) < 0) {
			// printf("No more sync packets\n");
			break;
		}

		for (;;) {
			if (pt_pkt_next(decoder, &packet, sizeof(packet)) < 0) {
				// printf("Error reding packet\n");
				break;
			}

			process_packet(&packet, trace_bits, coverage_kind);
		}
	}

	pt_pkt_free_decoder(decoder);
}
