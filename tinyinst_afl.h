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

#ifndef TINYINST_AFL_H
#define TINYINST_AFL_H

extern "C" int tinyinst_init(int argc, char** argv);
extern "C" void tinyinst_set_fuzzer_id(char* fuzzer_id);
extern "C" int tinyinst_run(char** argv, uint32_t timeout);
extern "C" void tinyinst_killtarget();

#endif // TINYINST_AFL_H
