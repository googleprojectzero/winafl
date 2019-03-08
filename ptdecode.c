/*
  WinAFL - Intel PT decoding
  ------------------------------------------------

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
#include <string.h>
#include <stdbool.h>
#include "windows.h"

#include "intel-pt.h"
#include "pt_cpu.h"
#include "pt_cpuid.h"
#include "pt_opcodes.h"
#include "pt_retstack.h"
#include "pt_block_decoder.h"

#include "types.h"
#include "config.h"
#include "debug.h"

#include "winaflpt.h"
#include "ptdecode.h"

#define PPT_EXT 0xFF

uint32_t previous_offset;
uint64_t previous_ip;

extern address_range* coverage_ip_ranges;
extern size_t num_ip_ranges;
static address_range* current_range;

extern u8 *trace_bits;

#define MAX_TRACELET_SIZE 100 // just a hint, the tracelets could end up larger
#define MIN_TRACELET_SIZE 20 // just a hint, the tracelets could end up smaller

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

static unsigned char psb_and_psbend[18] = {
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
	0x02, 0x23
};

typedef struct decoder_state_t {
	uint64_t query_ip;
	uint64_t block_ip;
	uint8_t mode;
} decoder_state;

typedef struct tracelet_cache_node_t {
	uint64_t hash;
	size_t size;

	struct tracelet_cache_node_t *hash_prev;
	struct tracelet_cache_node_t *hash_next;

	struct tracelet_cache_node_t *lru_prev;
	struct tracelet_cache_node_t *lru_next;

	decoder_state state_prev;
	decoder_state state_next;

	uint8_t stack_removed;
	uint8_t stack_added;

	uint64_t *stack_prev;
	uint64_t *stack_next;

	uint32_t tracelet_size;
	unsigned char * tracelet;

	uint32_t map_update_size;
	uint32_t *map_offsets;
	uint8_t *map_updates;

} tracelet_cache_node;

struct tracelet_cahe_t {
	tracelet_cache_node **hashtable;

	tracelet_cache_node *lru_first;
	tracelet_cache_node *lru_last;

	size_t size;
	size_t num_entries;

	size_t max_size;
	size_t max_entries;
};

static struct tracelet_cahe_t tracelet_cache;

struct coverage_cache_t {
	uint32_t index_buffer[MAP_SIZE];
	// need + 2 for edge coverage
	uint32_t map_offsets[MAP_SIZE + 2];
	uint8_t counters[MAP_SIZE + 2];
	uint32_t size;
};

void tracelet_coverage_init(struct coverage_cache_t *coverage_cache) {
	memset(coverage_cache->index_buffer, 0, MAP_SIZE * sizeof(coverage_cache->index_buffer[0]));
	coverage_cache->size = 0;
}

void tracelet_coverage_clear(struct coverage_cache_t *coverage_cache, int coverage_kind) {
	if (!coverage_cache->size) return;

	uint32_t from = 0;
	uint32_t to = coverage_cache->size;

	if (coverage_kind == COVERAGE_EDGE) {
		// the first and the last value have special meaning
		// in the case of edge coverage
		from++;
		to--;
	}

	for (uint32_t i = from; i < to; i++) {
		coverage_cache->index_buffer[coverage_cache->map_offsets[i]] = 0;
	}
	coverage_cache->size = 0;
}

void tracelet_coverage_add_bb(struct coverage_cache_t *coverage_cache, uint32_t offset) {
	offset = offset % MAP_SIZE;

	if (coverage_cache->index_buffer[offset]) {
		coverage_cache->counters[coverage_cache->index_buffer[offset] - 1]++;
	} else {
		coverage_cache->index_buffer[offset] = coverage_cache->size + 1;
		coverage_cache->map_offsets[coverage_cache->size] = offset;
		coverage_cache->counters[coverage_cache->size] = 1;
		coverage_cache->size++;
	}
}

void tracelet_coverage_add_edge(struct coverage_cache_t *coverage_cache, uint32_t offset) {
	uint32_t edge;
	// don't touch the global previous_offset while building the cache
	// we'll update everything once the cache gets replayed
	uint32_t previous_offset;

	if (!coverage_cache->size) {
		// store the first offset as the first value
		coverage_cache->map_offsets[0] = offset;
		coverage_cache->counters[0] = 0;
		coverage_cache->size = 2;
	} else {
		previous_offset = coverage_cache->map_offsets[coverage_cache->size - 1];

		edge = (offset ^ previous_offset) % MAP_SIZE;

		if (coverage_cache->index_buffer[edge]) {
			coverage_cache->counters[coverage_cache->index_buffer[edge]]++;
		} else {
			coverage_cache->index_buffer[edge] = coverage_cache->size - 1;
			coverage_cache->map_offsets[coverage_cache->size - 1] = edge;
			coverage_cache->counters[coverage_cache->size - 1] = 1;
			coverage_cache->size++;
		}
	}

	// always store the previous offset as the last value
	previous_offset = offset >> 1;
	coverage_cache->map_offsets[coverage_cache->size - 1] = previous_offset;
	coverage_cache->counters[coverage_cache->size - 1] = 0;
}

static inline uint64_t djb2(unsigned char *data, size_t size) {
	uint64_t hash = 5381;

	for (size_t i = 0; i < size; i++) {
		hash = (hash << 5) + hash + data[i];
	}

	return hash;
}

void tracelet_cache_init(size_t max_entries, size_t max_size) {
	tracelet_cache.max_entries = max_entries;
	tracelet_cache.max_size = max_size;

	tracelet_cache.hashtable = (tracelet_cache_node **)calloc(max_entries, sizeof(tracelet_cache_node *));

	tracelet_cache.lru_first = NULL;
	tracelet_cache.lru_last = NULL;

	tracelet_cache.size = 0;
	tracelet_cache.num_entries = 0;
}

// sets the node as the least recently used
void cache_node_touch(tracelet_cache_node *node) {
	// printf("accessing %p in cache\n", node);

	if (!node->lru_prev) return; //already at the beginning
	else node->lru_prev->lru_next = node->lru_next;

	if (node->lru_next) node->lru_next->lru_prev = node->lru_prev;
	else tracelet_cache.lru_last = node->lru_prev;

	node->lru_prev = NULL;
	node->lru_next = tracelet_cache.lru_first;
	if (node->lru_next) node->lru_next->lru_prev = node;
	tracelet_cache.lru_first = node;
}

void cache_node_remove(tracelet_cache_node *node) {
	// printf("removing %p from cache\n", node);

	if (node->lru_prev) node->lru_prev->lru_next = node->lru_next;
	else tracelet_cache.lru_first = node->lru_next;

	if (node->lru_next) node->lru_next->lru_prev = node->lru_prev;
	else tracelet_cache.lru_last = node->lru_prev;

	if (node->hash_prev) node->hash_prev->hash_next = node->hash_next;
	else tracelet_cache.hashtable[node->hash % tracelet_cache.max_entries] = node->hash_next;

	if (node->hash_next) node->hash_next->hash_prev = node->hash_prev;

	tracelet_cache.num_entries--;
	tracelet_cache.size -= node->size;

	free(node);
}

void cache_remove_lru() {
	tracelet_cache_node *node = tracelet_cache.lru_last;
	if (node) cache_node_remove(node);
}

void cache_node_add(tracelet_cache_node *node) {
	// printf("adding %p to cache\n", node);

	while (tracelet_cache.num_entries >= tracelet_cache.max_entries) cache_remove_lru();
	while ((tracelet_cache.size + node->size) >= tracelet_cache.max_size) cache_remove_lru();

	tracelet_cache_node *prev_first;

	prev_first = tracelet_cache.hashtable[node->hash % tracelet_cache.max_entries];
	tracelet_cache.hashtable[node->hash % tracelet_cache.max_entries] = node;

	node->hash_prev = NULL;
	node->hash_next = prev_first;
	if (prev_first) prev_first->hash_prev = node;

	prev_first = tracelet_cache.lru_first;
	tracelet_cache.lru_first = node;

	node->lru_prev = NULL;
	node->lru_next = prev_first;
	if (prev_first) prev_first->lru_prev = node;
	else tracelet_cache.lru_last = node;

	tracelet_cache.num_entries++;
	tracelet_cache.size += node->size;
}

tracelet_cache_node *cache_find_node(uint64_t hash, decoder_state *state, unsigned char *tracelet, size_t tracelet_size, struct pt_retstack *retstack) {
	tracelet_cache_node *node = tracelet_cache.hashtable[hash % tracelet_cache.max_entries];

	while (node) {
		if ((node->hash == hash) &&
			(node->state_prev.block_ip == state->block_ip) &&
			(node->state_prev.query_ip == state->query_ip) &&
			(node->state_prev.mode == state->mode) &&
			(node->tracelet_size == tracelet_size) &&
			(memcmp(node->tracelet, tracelet, tracelet_size) == 0))
		{

			uint8_t top = retstack->top;
			size_t i;
			for (i = 0; i < node->stack_removed; i++) {
				if (top == retstack->bottom) break;
				top = (!top ? pt_retstack_size : top - 1);
				if (retstack->stack[top] != node->stack_prev[i]) break;
			}
			if (i == node->stack_removed) return node; // finally

		}
		node = node->hash_next;
	}

	return NULL;
}

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

// function that was used to build the lookup tables for the packet decoder
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

// sign extend
inline static uint64_t sext(uint64_t val, uint8_t sign) {
	uint64_t signbit, mask;

	signbit = 1ull << (sign - 1);
	mask = ~0ull << sign;

	return val & signbit ? val | mask : val & ~mask;
}

// finds the next psb packet in the data buffer
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

// checks if the IP address is in one of the modules we are interested in
// and updates the coverage map
inline static int update_coverage_map(uint64_t next_ip, int coverage_kind) {
	uint32_t offset;

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

	offset = (uint32_t)(next_ip - current_range->start);

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

// checks if the IP address is in one of the modules we are interested in
// and updates the coverage_cache datastructure
inline static int update_coverage_cache(struct coverage_cache_t *coverage_cache,
	uint64_t next_ip, int coverage_kind)
{

	uint32_t offset;

	if (next_ip < current_range->start) {
		do {
			current_range--;
		} while (next_ip < current_range->start);
	}
	else if (next_ip > current_range->end) {
		do {
			current_range++;
		} while (next_ip > current_range->end);
	}

	if (!current_range->collect) return 0;

	// printf("ip: %p\n", (void*)next_ip);

	offset = (uint32_t)(next_ip - current_range->start);

	switch (coverage_kind) {
	case COVERAGE_BB:
		tracelet_coverage_add_bb(coverage_cache, offset);
		break;
	case COVERAGE_EDGE:
		tracelet_coverage_add_edge(coverage_cache, offset);
		break;
	}

	return 1;
}

// gets the opcode and the size of the next packet in the trace buffer
static inline int get_next_opcode(unsigned char **data_p, size_t *size_p, 
	unsigned char *opcode_p, unsigned char *opcodesize_p)
{

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

// returns the type of the first packet or ppt_invalid
int get_next_tracelet(unsigned char **data, size_t *size,
	unsigned char **tracelet_data, size_t *tracelet_size)
{
	unsigned char opcode;
	unsigned char opcodesize;
	unsigned char previous_opcode = ppt_invalid;
	int ret = ppt_tnt_8;

	while (*size) {

		if (!get_next_opcode(data, size, &opcode, &opcodesize))
			return ppt_invalid;

		if (opcode == ppt_invalid) return ppt_invalid;

		// printf("packet type: %d\n", opcode);

		switch (opcode) {
		case ppt_tnt_8:
		case ppt_tnt_64:
			// merge tiny tracelets
			if (*tracelet_size > MIN_TRACELET_SIZE) {
				// always cut before tnt preceeded by non-tnt
				if (previous_opcode != ppt_invalid &&
					previous_opcode != ppt_tnt_8 &&
					previous_opcode != ppt_tnt_64)
				{
					return ret;
				}
				// cut very long streams of tnt packets
				if (*tracelet_size > MAX_TRACELET_SIZE) {
					return ret;
				}
			}
			memcpy(*tracelet_data, *data, opcodesize);
			*tracelet_data += opcodesize;
			*tracelet_size += opcodesize;
			*size -= opcodesize;
			*data += opcodesize;
			previous_opcode = opcode;
			break;
		case ppt_psb:
			// let the caller know there is a psb in this tracelet
			ret = ppt_psb;
		case ppt_psbend:
		case ppt_fup:
		case ppt_tip:
		case ppt_tip_pge:
		case ppt_tip_pgd:
		case ppt_ovf:
		case ppt_mode:
			// just copy these packets
			memcpy(*tracelet_data, *data, opcodesize);
			*tracelet_data += opcodesize;
			*tracelet_size += opcodesize;
			*size -= opcodesize;
			*data += opcodesize;
			previous_opcode = opcode;
			break;
		default:
			// skip over all other packets
			*size -= opcodesize;
			*data += opcodesize;
			break;
		}
	}

	return ret;
}

// checks if the trace starts with the expected IP address
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

// fast decoder that decodes only tip (and related packets)
// and skips over the reset
void decode_trace_tip_fast(unsigned char *data, size_t size, int coverage_kind) {
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
		update_coverage_map(next_ip, coverage_kind);
	}

    size -= opcodesize;
    data += opcodesize;
  }
}

// process a sinle IPT packet and update AFL map
inline static void process_packet(struct pt_packet *packet, int coverage_kind) {
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
		update_coverage_map(next_ip, coverage_kind);
	}
}

// decodes only TIP packets using the reference implementation
void decode_trace_tip_reference(unsigned char *trace_data, size_t trace_size,
	int coverage_kind)
{
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

			process_packet(&packet, coverage_kind);
		}
	}

	pt_pkt_free_decoder(decoder);
}


// looks up if we already have the tracelet in cache and if so update
// the state and coverage from the cache entry
inline static bool process_tracelet_from_cache(uint64_t hash,
	decoder_state *state, unsigned char *tracelet, 
	size_t tracelet_size, struct pt_retstack *retstack,
	int coverage_kind)
{

	tracelet_cache_node *cache_node = cache_find_node(hash, state, tracelet, tracelet_size, retstack);

	if (!cache_node) return false;

	// mark the node as least recently used
	cache_node_touch(cache_node);

	// update state from cache
	*state = cache_node->state_next;

	// update stack if needed
	if (cache_node->stack_removed || cache_node->stack_added) {
		uint8_t top, bottom;
		top = retstack->top;
		bottom = retstack->bottom;

		for (uint32_t i = 0; i < cache_node->stack_removed; i++) {
			top = (!top ? pt_retstack_size : top - 1);
		}

		for (uint32_t i = 0; i < cache_node->stack_added; i++) {
			retstack->stack[top] = cache_node->stack_next[i];
			top = (top == pt_retstack_size ? 0 : top + 1);
			if (bottom == top) bottom = (bottom == pt_retstack_size ? 0 : bottom + 1);
		}

		retstack->top = top;
		retstack->bottom = bottom;
	}

	// update trace_bits
	switch (coverage_kind) {
	case COVERAGE_BB:
		for (uint32_t i = 0; i < cache_node->map_update_size; i++) {
			trace_bits[cache_node->map_offsets[i]] += cache_node->map_updates[i];
		}
		break;
	case COVERAGE_EDGE:
		if (cache_node->map_update_size) {
			trace_bits[(cache_node->map_offsets[0] ^ previous_offset) % MAP_SIZE]++;
			for (uint32_t i = 1; i < cache_node->map_update_size - 1; i++) {
				trace_bits[cache_node->map_offsets[i]] += cache_node->map_updates[i];
			}
			previous_offset = cache_node->map_offsets[cache_node->map_update_size - 1];
		}
		break;
	}

	return true;
}

// processes a tracelet using the reference decoder
inline static int process_tracelet_reference(struct pt_block_decoder *decoder,
	uint8_t *tracelet_end, decoder_state *state_before, decoder_state *state_after,
	struct pt_retstack *retstack_before, int *stack_added, int *stack_removed,
	struct coverage_cache_t *coverage_cache, int coverage_kind,
	bool first_tracelet, bool track_stack, bool *skip_next)
{

	int stack_last;
	int status;

	struct pt_event event;
	struct pt_block block;

	decoder->query.config.end = tracelet_end;
	status = pt_blk_sync_set(decoder, 0);

	if (status < 0) return status;

	// restore state
	if (!first_tracelet) {
		decoder->query.ip.ip = state_before->query_ip;
		decoder->query.ip.have_ip = 1;
		decoder->query.ip.suppressed = 0;
		decoder->enabled = 1;
		decoder->mode = state_before->mode;
		decoder->ip = state_before->block_ip;
		decoder->retstack = *retstack_before;
	}

	stack_last = retstack_before->top;

	*stack_added = 0;
	*stack_removed = 0;

	tracelet_coverage_clear(coverage_cache, coverage_kind);

	for (;;) {
		// we aren't really interested in events
		// but have to empty the event queue
		while (status & pts_event_pending) {
			status = pt_blk_event(decoder, &event, sizeof(event));
			if (status < 0)
				break;

			// printf("event %d\n", event.type);
		}

		if (status < 0) {
			break;
		}

		status = pt_blk_next(decoder, &block, sizeof(block));

		if (track_stack) {
			if (decoder->retstack.top != stack_last) {
				if ((decoder->retstack.top == stack_last - 1) ||
					(decoder->retstack.top == 64) && (stack_last == 0)) {
					*stack_added -= 1;
					if (*stack_added < *stack_removed) *stack_removed = *stack_added;
				}
				else if ((decoder->retstack.top == stack_last + 1) ||
					(decoder->retstack.top == 0) && (stack_last == 64)) {
					*stack_added += 1;
				}
				else {
					FATAL("Error: unexpected stack change");
				}
				stack_last = decoder->retstack.top;
			}
		}

		if (status < 0) {
			// printf("status: %d\n", status);
			break;
		}

		if (!*skip_next) {
			*skip_next = false;
			update_coverage_cache(coverage_cache, block.ip, coverage_kind);
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
		if (block.iclass == ptic_other) *skip_next = true;
		else *skip_next = false;
	}

	state_after->query_ip = decoder->query.ip.ip;
	state_after->mode = decoder->mode;
	state_after->block_ip = block.ip;

	switch (coverage_kind) {
	case COVERAGE_BB:
		for (uint32_t i = 0; i < coverage_cache->size; i++) {
			trace_bits[coverage_cache->map_offsets[i]] += coverage_cache->counters[i];
		}
		break;
	case COVERAGE_EDGE:
		if (coverage_cache->size) {
			trace_bits[(coverage_cache->map_offsets[0] ^ previous_offset) % MAP_SIZE]++;
			for (uint32_t i = 1; i < coverage_cache->size - 1; i++) {
				trace_bits[coverage_cache->map_offsets[i]] += coverage_cache->counters[i];
			}
			previous_offset = coverage_cache->map_offsets[coverage_cache->size - 1];
		}
		break;
	}

	return status;
}


// constructs the cache node from the decoder state, tracelet etc
// and adds it to the cache
static inline void add_cache_node(
	uint8_t *tracelet, size_t tracelet_size, uint64_t hash,
	decoder_state *state_before, decoder_state *state_after,
	struct pt_retstack *retstack_before, struct pt_retstack *retstack_after,
	int stack_added, int stack_removed,
	struct coverage_cache_t *coverage_cache)
{
	stack_removed = -stack_removed;
	stack_added += stack_removed;

	if (stack_removed > (pt_retstack_size + 1)) stack_removed = (pt_retstack_size + 1);

	if (stack_added < 0) stack_added = 0;
	if (stack_added >(pt_retstack_size + 1)) stack_added = (pt_retstack_size + 1);

	size_t node_size = sizeof(tracelet_cache_node) +
		stack_removed * sizeof(uint64_t) + stack_added * sizeof(uint64_t) +
		coverage_cache->size * sizeof(uint32_t) + coverage_cache->size * sizeof(uint8_t) +
		tracelet_size;

	tracelet_cache_node *cache_node = (tracelet_cache_node *)malloc(node_size);

	cache_node->size = node_size;
	cache_node->hash = hash;

	uint8_t* ptr = (uint8_t*)cache_node + sizeof(tracelet_cache_node);
	cache_node->stack_prev = (uint64_t *)ptr;
	cache_node->stack_removed = stack_removed;
	ptr += stack_removed * sizeof(uint64_t);
	cache_node->stack_next = (uint64_t *)ptr;
	cache_node->stack_added = stack_added;
	ptr += stack_added * sizeof(uint64_t);
	cache_node->map_offsets = (uint32_t *)ptr;
	ptr += coverage_cache->size * sizeof(uint32_t);
	cache_node->map_updates = ptr;
	cache_node->map_update_size = coverage_cache->size;
	ptr += coverage_cache->size * sizeof(uint8_t);
	cache_node->tracelet = ptr;
	cache_node->tracelet_size = (uint32_t)tracelet_size;

	uint8_t top;
	top = retstack_before->top;
	for (int i = 0; i < stack_removed; i++) {
		top = (!top ? pt_retstack_size : top - 1);
		cache_node->stack_prev[i] = retstack_before->stack[top];
	}

	top = retstack_after->top;
	for (int i = 0; i < stack_added; i++) {
		top = (!top ? pt_retstack_size : top - 1);
		cache_node->stack_next[stack_added - i - 1] = retstack_after->stack[top];
	}

	memcpy(cache_node->map_offsets, coverage_cache->map_offsets, coverage_cache->size * sizeof(uint32_t));
	memcpy(cache_node->map_updates, coverage_cache->counters, coverage_cache->size * sizeof(uint8_t));

	memcpy(cache_node->tracelet, tracelet, tracelet_size);

	cache_node->state_prev = *state_before;
	cache_node->state_next = *state_after;

	cache_node_add(cache_node);
}

// uses a faster basic block decoder to decode the full trace
// tl;dr the faster decoder is essentially a caching layer on top of the
// reference decoder
// needs to have access to executable memory of the process that generated
// the trace (passed through pt_image)
void analyze_trace_full_fast(unsigned char *trace_data, size_t trace_size,
	int coverage_kind, struct pt_image *image, bool skip_first_bb)
{
	// some stats
	int num_tracelets=0, num_cache_hits=0;

	size_t tracelet_buffer_size = trace_size + sizeof(psb_and_psbend);
	unsigned char *tracelet_buffer = malloc(tracelet_buffer_size);
	size_t tracelet_size;

	memcpy(tracelet_buffer, psb_and_psbend, sizeof(psb_and_psbend));
	unsigned char *buffer_after_psb = tracelet_buffer + sizeof(psb_and_psbend);
	unsigned char *tracelet_start;

	decoder_state state, state_next;
	struct pt_retstack retstack;
	retstack.top = 0;
	retstack.bottom = 0;

	uint64_t hash;

	int stack_removed;
	int stack_added;

	struct pt_block_decoder *decoder;
	struct pt_config config;

	bool skip_next = skip_first_bb;
	bool first_tracelet = true;
	bool use_cache = false;

	previous_offset = 0;
	previous_ip = 0;
	current_range = &(coverage_ip_ranges[0]);

	struct coverage_cache_t *coverage_cache =
		(struct coverage_cache_t *)malloc(sizeof(struct coverage_cache_t));
	tracelet_coverage_init(coverage_cache);

	pt_config_init(&config);
	pt_cpu_read(&config.cpu);
	pt_cpu_errata(&config.errata, &config.cpu);
	config.begin = tracelet_buffer;
	config.end = tracelet_buffer + tracelet_buffer_size;

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

	int ret = pt_blk_set_image(decoder, image);

	int status;

	if (!findpsb(&trace_data, &trace_size)) {
		FATAL("No sync packets in trace\n");
		return;
	}

	for (;;) {
		tracelet_start = buffer_after_psb;
		tracelet_size = 0;

		int ret = get_next_tracelet(&trace_data, &trace_size, &tracelet_start, &tracelet_size);

		if (!tracelet_size) break;

		if (ret == ppt_invalid) {
			if (!findpsb(&trace_data, &trace_size)) {
				break;
			}
			first_tracelet = true;
			skip_next = true;
			continue;
		}
		else if (ret == ppt_psb) {
			// don't use cache for tracelets containing psb
			// psbs are going to mess up our stack tracking
			use_cache = false;
		}
		else {
			use_cache = true;
		}

		if (skip_next) {
			use_cache = false;
		}

		num_tracelets++;

		// printf("tracelet size: %llu\n", tracelet_size);

		hash = djb2(buffer_after_psb, tracelet_size);

		// printf("hash: %llx\n", hash);

		if (use_cache &&
			process_tracelet_from_cache(hash, &state, buffer_after_psb,
				tracelet_size, &retstack, coverage_kind))
		{
			num_cache_hits++;
			continue;
		}

		status = process_tracelet_reference(decoder, tracelet_start,
			&state, &state_next, &retstack, &stack_added, &stack_removed,
			coverage_cache, coverage_kind, first_tracelet, use_cache,
			&skip_next);

		first_tracelet = false;

		if ((status < 0) && (status != -pte_eos)) {
			if (!findpsb(&trace_data, &trace_size)) {
				printf("cant't sync\n");
				break;
			}
			skip_next = true;
			continue;
		}

		if (use_cache && !skip_next) {
			// create a new cache node and add it to the cache
			add_cache_node(buffer_after_psb, tracelet_size, hash,
				&state, &state_next, &retstack, &decoder->retstack,
				stack_added, stack_removed, coverage_cache);
		}

		// switch state
		state = state_next;
		retstack = decoder->retstack;
	}

	free(coverage_cache);
	free(tracelet_buffer);

	pt_blk_free_decoder(decoder);

	// printf("Cache hits: %d/%d (%g%%)\n", num_cache_hits, num_tracelets,
	// 	((float)num_cache_hits / num_tracelets) * 100);
	// printf("tracelet cache num entries: %llu, size: %llu\n",
	// 	tracelet_cache.num_entries, tracelet_cache.size);
}

// uses Intel's reference basic block decoder to decode the full trace
// needs to have access to executable memory of the process that generated
// the trace (passed through pt_image)
void analyze_trace_full_reference(unsigned char *trace_data, size_t trace_size,
	int coverage_kind, struct pt_image *image, bool skip_first_bb) {

	struct pt_block_decoder *decoder;
	struct pt_config config;
	struct pt_event event;
	struct pt_block block;

	bool skip_next = skip_first_bb;

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
				update_coverage_map(block.ip, coverage_kind);
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
			if (block.iclass == ptic_other) skip_next = true;
			else skip_next = false;
		}
	}

	pt_blk_free_decoder(decoder);
}
