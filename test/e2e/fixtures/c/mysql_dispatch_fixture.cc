// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

#include <chrono>
#include <cstring>
#include <thread>

enum enum_server_command {
    COM_QUERY = 3,
};

struct THD {};

__attribute__((noinline, visibility("default"))) int dispatch_command(
    enum_server_command command, THD *thd, char *packet, unsigned int packet_length, bool blocking, bool is_com_multi) {
    asm volatile(""
                 :
                 : "r"(command), "r"(thd), "r"(packet), "r"(packet_length), "r"(blocking), "r"(is_com_multi)
                 : "memory");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    THD thd;
    for (int attempt = 0; attempt < 3; ++attempt) {
        dispatch_command(COM_QUERY, &thd, argv[1], static_cast<unsigned int>(std::strlen(argv[1])), true, false);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
