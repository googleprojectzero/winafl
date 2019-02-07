typedef struct _module_info_t {
	char module_name[MAX_PATH];
	int isid;
	void *base;
	size_t size;
	struct _module_info_t *next;
} module_info_t;

typedef struct _address_range {
	uint64_t start;
	uint64_t end;
	char collect; // collect coverage for range or not
} address_range;

int check_trace_start(unsigned char *data, size_t size, uint64_t expected_ip);

void analyze_trace_buffer_full(unsigned char *trace_data, size_t trace_size, u8 *trace_bits, int coverage_kind, module_info_t* modules, struct pt_image_section_cache *section_cache);
void decode_trace_tip_fast(unsigned char *data, size_t size, u8 *trace_bits, int coverage_kind);
void decode_trace_tip_reference(unsigned char *trace_data, size_t trace_size, u8 *trace_bits, int coverage_kind);