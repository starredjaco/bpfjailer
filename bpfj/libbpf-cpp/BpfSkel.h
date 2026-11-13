// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <errno.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <utility>
#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/libbpf-cpp/BpfSkelBase.h"

namespace bpfj::libbpf {

// Serializes the skeleton open phase, libelf not being thread-safe.
// Out-of-line in BpfSkel.cpp so every BpfSkel<T> shares one mutex; a static
// local in the templated open() would be per-type.
std::mutex& skeletonOpenMutex() noexcept;

namespace detail {

template <typename T>
concept HasMaps = requires(T t) { t.maps; };

template <typename T>
concept HasProgs = requires(T t) { t.progs; };

template <typename T>
concept HasLinks = requires(T t) { t.links; };

template <typename T>
concept HasRodata = requires(T t) { t.rodata; };

template <typename T>
concept HasData = requires(T t) { t.data; };

template <typename T>
concept HasBss = requires(T t) { t.bss; };

inline bool kernelSupportsHeapSyscall() noexcept {
  struct utsname name{};
  unsigned int major = 0;
  unsigned int minor = 0;
  if (::uname(&name) != 0 ||
      std::sscanf(name.release, "%u.%u", &major, &minor) != 2) {
    return false;
  }
  return major > 6 || (major == 6 && minor >= 11);
}

// bpfj_heap_arena declares its byte window in 4 KiB pages. The kernel counts
// arena max_entries in native pages and rejects a window over 4 GiB.
inline std::uint32_t heapArenaMaxEntries(long pageSize) noexcept {
  return pageSize > 0
      ? bpfj_heap_arena_max_entries(static_cast<std::uint64_t>(pageSize))
      : 0;
}

inline std::uint32_t heapArenaMaxEntries() noexcept {
  return heapArenaMaxEntries(::sysconf(_SC_PAGESIZE));
}

// Sizes bpfj_heap_arena to `entries` with `setMaxEntries`, and returns false
// if that fails. 0 means an unsupported page size. Then the arena keeps its
// declared size, so that a loader can still turn the arena off. heap::init()
// rejects that size.
template <typename SetMaxEntries>
[[nodiscard]] bool sizeHeapArena(
    std::uint32_t entries,
    const SetMaxEntries& setMaxEntries) noexcept {
  return entries == 0 || setMaxEntries(entries) == 0;
}

} // namespace detail

template <typename Skel>
class BpfSkel final : public BpfSkelBase {
 public:
  BpfSkel() noexcept = default;

  ~BpfSkel() noexcept override {
    if (skel_) {
      destroy();
    }
  }

  BpfSkel(const BpfSkel&) = delete;

  BpfSkel& operator=(const BpfSkel&) = delete;

  void swap(BpfSkel& other) noexcept {
    std::swap(skel_, other.skel_);
  }

  BpfSkel(BpfSkel&& other) noexcept {
    swap(other);
  }
  BpfSkel& operator=(BpfSkel&& other) noexcept {
    swap(other);
    return *this;
  }

  [[nodiscard]] Expected<> open(
      const std::optional<OpenOpts>& opts = {}) noexcept override {
    std::lock_guard<std::mutex> guard(skeletonOpenMutex());
    return openUnlocked(opts);
  }

  [[nodiscard]] Expected<> load() noexcept override {
    if (auto error = Skel::load(skel_)) {
      return makeUnexpected(
          Error(std::errc(-error), "failed to load BPF skeleton"));
    }

    return unit;
  }

  [[nodiscard]] Expected<> openAndLoad() noexcept override {
    std::lock_guard<std::mutex> guard(skeletonOpenMutex());
    if (auto result = openUnlocked(); !result) {
      return result;
    }
    return load();
  }

  [[nodiscard]] Expected<> attach() noexcept override {
    if (auto error = Skel::attach(skel_)) {
      return makeUnexpected(
          Error(std::errc(-error), "failed to attach BPF skeleton"));
    }

    return unit;
  }

  void detach() noexcept override {
    // The generated Skel::detach() dereferences its argument unconditionally.
    // Detaching a skeleton that was never opened, or that was destroyed,
    // faults. This null check is not a race guard, because skel_ is a plain
    // pointer. Callers must keep the skeleton alive and serialize detach()
    // with destroy(). BpfHandler::stop() relies on its caller for this.
    if (!skel_) {
      return;
    }
    Skel::detach(skel_);
  }

  void destroy() noexcept override {
    Skel::destroy(skel_);
    skel_ = nullptr;
  }

  [[nodiscard]] static Expected<std::shared_ptr<BpfSkel>> create(
      const std::optional<OpenOpts>& opts = {}) {
    auto skel = std::make_shared<BpfSkel>();
    if (auto res = skel->open(opts); !res) {
      return makeUnexpected(res.error());
    }

    return skel;
  }

  BpfObject obj() noexcept override {
    return BpfObject(skel_->obj);
  }

  auto get() noexcept {
    return skel_;
  }

  auto skeleton() noexcept {
    return skel_->skeleton;
  }

  template <detail::HasMaps T = Skel>
  auto& maps() noexcept {
    return skel_->maps;
  }

  template <detail::HasProgs T = Skel>
  auto& progs() noexcept {
    return skel_->progs;
  }

  template <detail::HasLinks T = Skel>
  auto& links() noexcept {
    return skel_->links;
  }

  template <detail::HasRodata T = Skel>
  auto& rodata() noexcept {
    return *skel_->rodata;
  }

  template <detail::HasData T = Skel>
  auto& data() noexcept {
    return *skel_->data;
  }

  template <detail::HasBss T = Skel>
  auto& bss() noexcept {
    return *skel_->bss;
  }

 private:
  [[nodiscard]] Expected<> openUnlocked(
      const std::optional<OpenOpts>& opts = {}) noexcept {
    const struct bpf_object_open_opts* optsPtr = nullptr;
    if (opts) {
      optsPtr = &opts->opts_;
    }

    skel_ = Skel::open(optsPtr);
    if (!skel_) {
      return makeUnexpected(Error::fromErrno("failed to open BPF skeleton"));
    }

    if constexpr (requires { skel_->progs.bpfj_heap_syscall; }) {
      if (!detail::kernelSupportsHeapSyscall()) {
        const int error =
            bpf_program__set_autoload(skel_->progs.bpfj_heap_syscall, false);
        if (error != 0) {
          return makeUnexpected(makeError(
              std::errc::invalid_argument,
              "failed to disable unsupported heap syscall program"));
        }
      }
    }

    // Every loader of an arena-backed skeleton opens it here, so size the
    // arena once for all of them. A reused fd replaces this with its own size.
    if constexpr (requires { skel_->maps.bpfj_heap_arena; }) {
      auto* const arena = skel_->maps.bpfj_heap_arena;
      if (!detail::sizeHeapArena(
              detail::heapArenaMaxEntries(), [arena](std::uint32_t entries) {
                return bpf_map__set_max_entries(arena, entries);
              })) {
        return makeUnexpected(makeError(
            std::errc::invalid_argument,
            "failed to size the heap arena in native pages"));
      }
    }

    return unit;
  }

  Skel* skel_ = nullptr;
};

} // namespace bpfj::libbpf

namespace std {

template <typename T>
void swap(
    bpfj::libbpf::BpfSkel<T>& lhs,
    bpfj::libbpf::BpfSkel<T>& rhs) noexcept {
  lhs.swap(rhs);
}

} // namespace std
