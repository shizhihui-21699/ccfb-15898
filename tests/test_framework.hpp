// A tiny, dependency-free test harness.  No gtest, no Catch: the whole point
// of this codebase is auditability, and that extends to the tests.
#pragma once

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

namespace rptest {

struct TestCase {
  std::string name;
  std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> r;
  return r;
}

struct Registrar {
  Registrar(const char* name, std::function<void()> fn) {
    registry().push_back({name, std::move(fn)});
  }
};

struct Failure {
  std::string msg;
};

inline int& failure_count() {
  static int n = 0;
  return n;
}

inline void fail(const char* file, int line, const std::string& msg) {
  std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, msg.c_str());
  ++failure_count();
}

}  // namespace rptest

#define TEST(name)                                                    \
  static void name();                                                 \
  static ::rptest::Registrar reg_##name(#name, name);                 \
  static void name()

#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) ::rptest::fail(__FILE__, __LINE__, "CHECK(" #cond ")");   \
  } while (0)

#define CHECK_EQ(a, b)                                                              \
  do {                                                                              \
    auto _va = (a);                                                                 \
    auto _vb = (b);                                                                 \
    if (!(_va == _vb))                                                              \
      ::rptest::fail(__FILE__, __LINE__, "CHECK_EQ(" #a ", " #b ")");              \
  } while (0)

#define CHECK_BYTES(a, b)                                                            \
  do {                                                                               \
    auto _va = (a);                                                                  \
    auto _vb = (b);                                                                  \
    if (_va.size() != _vb.size())                                                    \
      ::rptest::fail(__FILE__, __LINE__, "CHECK_BYTES size mismatch");               \
    else if (std::memcmp(_va.data(), _vb.data(), _va.size()) != 0)                   \
      ::rptest::fail(__FILE__, __LINE__, "CHECK_BYTES(" #a ", " #b ")");            \
  } while (0)
