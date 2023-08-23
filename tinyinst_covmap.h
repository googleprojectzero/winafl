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

#ifndef TINYINST_COVMAP_H
#define TINYINST_COVMAP_H

#include <string>
#include "tinyinst.h"

#define MAP_SIZE 65536

enum CovType {
  COVTYPE_BB,
  COVTYPE_EDGE
};

class TinyInstCovMap : public TinyInst {
public:
  virtual void Init(int argc, char **argv) override;
  void SetSHMName(std::string& shm_name);

protected:
  virtual void OnProcessExit() override;

  virtual void OnModuleInstrumented(ModuleInfo* module) override;
  virtual void OnModuleEntered(ModuleInfo *module, size_t entry_address) override;

  virtual void InstrumentBasicBlock(ModuleInfo *module, size_t bb_address) override;
  virtual void InstrumentEdge(ModuleInfo *previous_module,
                              ModuleInfo *next_module,
                              size_t previous_address,
                              size_t next_address) override;

  void EmitCoverageInstrumentation(ModuleInfo *module, uint32_t map_offset);

  uint32_t GetBBOffset(ModuleInfo* module, size_t bb_address);
  uint32_t GetEdgeOffset(ModuleInfo* module1,
                         ModuleInfo* module2,
                         size_t edge_address1,
                         size_t edge_address2);

private:
  void EnsureSharedMemory();

  CovType coverage_type;
  void* map_address;
  std::string shm_name;
};

#endif // TINYINST_COVMAP_H
