/*
  WinAFL - Intel PT instrumentation and presistence via debugger code
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

#define COVERAGE_BB 0
#define COVERAGE_EDGE 1

#define TRACE_BUFFER_SIZE_DEFAULT (128*1024) //should be a power of 2

#define TRACE_CACHE_SIZE_MIN 10000000
#define TRACE_CACHE_SIZE_MAX 100000000

bool findpsb(unsigned char **data, size_t *size);

int run_target_pt(char **argv, uint32_t timeout);
int pt_init(int argc, char **argv, char *module_dir);
void debug_target_pt(char **argv);