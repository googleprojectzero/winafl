/*
Copyright 2023 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "windows.h"
#include "tinyinst_covmap.h"
#include "common.h"

void TinyInstCovMap::Init(int argc, char **argv) {
  TinyInst::Init(argc, argv);

  coverage_type = COVTYPE_BB;
  char *option = GetOption("-covtype", argc, argv);
  if (option) {
    if (strcmp(option, "bb") == 0)
      coverage_type = COVTYPE_BB;
    else if (strcmp(option, "edge") == 0)
      coverage_type = COVTYPE_EDGE;
    else
      FATAL("Unknown coverage type");
  }

  map_address = NULL;
}

void TinyInstCovMap::SetSHMName(std::string &shm_name) {
  this->shm_name = shm_name;
}

void TinyInstCovMap::OnModuleInstrumented(ModuleInfo* module) {
  EnsureSharedMemory();
}

void TinyInstCovMap::EnsureSharedMemory() {
  if (map_address) return;

  if (shm_name.empty()) FATAL("Shared memory name is not set");

  HANDLE map_file;

  map_file = OpenFileMapping(
    FILE_MAP_ALL_ACCESS,
    FALSE,
    shm_name.c_str());

  if (map_file == NULL) FATAL("Error mapping shared memory");

  map_address = MapViewOfFile2(map_file,
    GetChildProcessHandle(),
    0,
    0,
    MAP_SIZE,
    0,
    PAGE_READWRITE);

  if (!map_address) FATAL("Error mapping shared memory");

  CloseHandle(map_file);
}

void TinyInstCovMap::EmitCoverageInstrumentation(ModuleInfo *module,
                                          uint32_t map_offset) {

  // common x86 assembly codes
  unsigned char PUSH_F[] = { 0x9c };
  unsigned char POP_F[] = { 0x9d };
  unsigned char PUSH_RAX[] = { 0x50 };
  unsigned char POP_RAX[] = { 0x58 };
  unsigned char INC_ADDR[] = { 0xFE, 0x05, 0xAA, 0xAA, 0xAA, 0xAA };
  unsigned char MOV_RAX_IMM64[] = { 0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
  unsigned char INC_MEM_RAX[] = { 0xFE, 0x00 };

  size_t address = (size_t)map_address + map_offset;

  if (sp_offset) {
    assembler_->OffsetStack(module, -sp_offset);
  }

  // pushf
  WriteCode(module, PUSH_F, sizeof(PUSH_F));

  if (child_ptr_size == 4) {

    // inc byte ptr[addr]
    WriteCode(module, INC_ADDR, sizeof(INC_ADDR));
    *(uint32_t*)(module->instrumented_code_local +
      module->instrumented_code_allocated - 4) =
      (uint32_t)address;

  } else {

    // push rax
    WriteCode(module, PUSH_RAX, sizeof(PUSH_RAX));

    // mov rax, addr
    WriteCode(module, MOV_RAX_IMM64, sizeof(MOV_RAX_IMM64));
    *(uint64_t*)(module->instrumented_code_local +
      module->instrumented_code_allocated - 8) =
      (uint64_t)address;

    // inc byte ptr[rax]
    WriteCode(module, INC_MEM_RAX, sizeof(INC_MEM_RAX));

    // pop rax
    WriteCode(module, POP_RAX, sizeof(POP_RAX));

  }

  // popf
  WriteCode(module, POP_F, sizeof(POP_F));

  if (sp_offset) {
    assembler_->OffsetStack(module, sp_offset);
  }
}

void TinyInstCovMap::InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) {
  if (coverage_type != COVTYPE_BB) return;

  uint32_t offset = GetBBOffset(module, bb_address);

  EmitCoverageInstrumentation(module, offset);
}

void TinyInstCovMap::InstrumentEdge(ModuleInfo *previous_module,
                             ModuleInfo *next_module, size_t previous_address,
                             size_t next_address) {
  if (coverage_type != COVTYPE_EDGE) return;

  uint32_t coverage_code =
      GetEdgeOffset(previous_module, next_module, previous_address, next_address);

  EmitCoverageInstrumentation(previous_module, coverage_code);
}

uint32_t TinyInstCovMap::GetBBOffset(ModuleInfo *module, size_t bb_address) {
  uint32_t offset = (uint32_t)((size_t)bb_address - (size_t)module->min_address);
  return offset % MAP_SIZE;
}

uint32_t TinyInstCovMap::GetEdgeOffset(ModuleInfo *module1,
                                     ModuleInfo *module2,
                                     size_t edge_address1,
                                     size_t edge_address2)
{
  uint32_t offset1 = 0;
  if (module1 && edge_address1)
    offset1 = (uint32_t)((size_t)edge_address1 - (size_t)module1->min_address);
  uint32_t offset2 = 0;
  if (module2 && edge_address2)
    offset2 = (uint32_t)((size_t)edge_address2 - (size_t)module2->min_address);

  return ((offset1 >> 1) ^ offset2) % MAP_SIZE;
}

void TinyInstCovMap::OnModuleEntered(ModuleInfo *module, size_t entry_address) {
  if (coverage_type == COVTYPE_BB) return;

  if (!map_address) return;

  uint8_t map_byte = 0;
  uint32_t map_offset = GetEdgeOffset(0, module, 0, entry_address);

  RemoteRead((char*)map_address + map_offset, &map_byte, sizeof(map_byte));
  map_byte++;
  RemoteWrite((char*)map_address + map_offset, &map_byte, sizeof(map_byte));
}

void TinyInstCovMap::OnProcessExit() {
  map_address = NULL;
  TinyInst::OnProcessExit();
}
