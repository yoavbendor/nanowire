// SPDX-License-Identifier: Apache-2.0
// Minimal test harness: CHECK / CHECK_EQ record failures and keep going; main returns non-zero
// when anything failed.
#pragma once

#include <cstdio>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace nwtest {
inline int& failures() {
  static int f = 0;
  return f;
}
inline int& checks() {
  static int c = 0;
  return c;
}
inline std::vector<std::pair<const char*, std::function<void()>>>& registry() {
  static std::vector<std::pair<const char*, std::function<void()>>> r;
  return r;
}
struct reg {
  reg(const char* n, std::function<void()> f) { registry().emplace_back(n, std::move(f)); }
};
inline int run_all() {
  for (auto& [n, f] : registry()) {
    const int before = failures();
    f();
    std::printf("%-48s %s\n", n, failures() == before ? "ok" : "FAILED");
  }
  std::printf("%d checks, %d failures\n", checks(), failures());
  return failures() == 0 ? 0 : 1;
}
}  // namespace nwtest

#define NW_CAT2(a, b) a##b
#define NW_CAT(a, b) NW_CAT2(a, b)
#define TEST(name)                                                         \
  static void name();                                                      \
  static nwtest::reg NW_CAT(name, _reg){#name, name};                      \
  static void name()
#define CHECK(...)                                                                       \
  do {                                                                                    \
    ++nwtest::checks();                                                                   \
    if (!(__VA_ARGS__)) {                                                                 \
      ++nwtest::failures();                                                               \
      std::printf("  %s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #__VA_ARGS__);           \
    }                                                                                     \
  } while (0)
#define CHECK_EQ(a, b)                                                                                      \
  do {                                                                                                      \
    ++nwtest::checks();                                                                                     \
    const auto nw_a = (a);                                                                                  \
    const auto nw_b = (b);                                                                                  \
    if (!(nw_a == nw_b)) {                                                                                  \
      ++nwtest::failures();                                                                                 \
      std::printf("  %s:%d: CHECK_EQ(%s, %s) failed: %lld vs %lld\n", __FILE__, __LINE__, #a, #b,          \
                  static_cast<long long>(nw_a), static_cast<long long>(nw_b));                              \
    }                                                                                                       \
  } while (0)
#define TEST_MAIN() \
  int main() { return nwtest::run_all(); }
