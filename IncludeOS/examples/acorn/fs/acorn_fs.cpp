// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015-2016 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "acorn_fs.hpp"

namespace acorn {

static size_t dir_count;
static size_t file_count;

static void
recursive_fs_dump(const std::vector<fs::Dirent>& entries, const int depth = 1)
{
  const int indent = (depth * 3);

  for (auto&& entry : entries) {
    if (entry.is_dir()) {
      if (entry.name() not_eq "."  and entry.name() not_eq "..") {
        ++dir_count;
        printf("%*c-[ %s ]\n", indent, '+', entry.name().c_str());
        entry.ls(
          [depth] (auto, auto entries) {
            recursive_fs_dump(*entries, (depth + 1));
          });
      } else {
        printf("%*c   %s\n", indent, '+', entry.name().c_str());
      }
    } else {
      printf("%*c-> %s\n", indent, '+', entry.name().c_str());
      ++file_count;
    }
  }

}

void list_static_content(const fs::File_system& fs)
{
  printf("%s\n",
  "================================================================================\n"
  "STATIC CONTENT LISTING\n"
  "================================================================================\n");
  dir_count  = 0;
  file_count = 0;
  recursive_fs_dump(*fs.ls("/").entries);
  printf("\n%u %s, %u %s\n", dir_count, "directories", file_count, "files");
  printf("%s",
  "================================================================================\n");
}

} //< namespace acorn
