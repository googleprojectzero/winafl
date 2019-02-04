#define COVERAGE_BB 0
#define COVERAGE_EDGE 1

bool findpsb(unsigned char **data, size_t *size);

int run_target_pt(char **argv, uint32_t timeout);
int pt_init(int argc, char **argv, char *module_dir);
void debug_target_pt(char **argv);