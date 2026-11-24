// SPDX-License-Identifier: Apache-2.0
#include <cstring>

#include "test_framework.hpp"

int main(int argc, char** argv) {
  const char* filter = argc > 1 ? argv[1] : nullptr;
  int run = 0;
  for (auto& tc : rptest::registry()) {
    if (filter && tc.name.find(filter) == std::string::npos) continue;
    std::printf("[ RUN  ] %s\n", tc.name.c_str());
    int before = rptest::failure_count();
    tc.fn();
    int after = rptest::failure_count();
    if (after == before)
      std::printf("[  OK  ] %s\n", tc.name.c_str());
    else
      std::printf("[ FAIL ] %s (%d failures)\n", tc.name.c_str(), after - before);
    ++run;
  }
  std::printf("\n%d test(s) run, %d failure(s)\n", run, rptest::failure_count());
  return rptest::failure_count() == 0 ? 0 : 1;
}
