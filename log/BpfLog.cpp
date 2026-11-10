// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "log/BpfLog.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "bpfj/enforce/bpf/types.h"
#include "bpfj/enforce/bpf/types_fs.h"
#include "bpfj/lib/bpf/logging.h"

namespace bpfjailer::log {

namespace {

[[nodiscard]] std::string_view boundedString(
    const char* buf,
    std::size_t size) noexcept {
  const char* end = std::find(buf, buf + size, '\0');
  return std::string_view(buf, static_cast<std::size_t>(end - buf));
}

[[nodiscard]] const char* fsReasonTracePrefix(__u8 reason) noexcept {
  switch (reason) {
    case BPFJ_FS_REASON_OPEN:
      return "open";
    case BPFJ_FS_REASON_UNLINK:
      return "unlink";
    case BPFJ_FS_REASON_LINK_OLD:
      return "link_old";
    case BPFJ_FS_REASON_LINK_NEW:
      return "link_new";
    case BPFJ_FS_REASON_MKNOD:
      return "mknod";
    case BPFJ_FS_REASON_RENAME_OLD:
      return "rename_old";
    case BPFJ_FS_REASON_RENAME_NEW:
      return "rename_new";
    case BPFJ_FS_REASON_RMDIR:
      return "rmdir";
    case BPFJ_FS_REASON_SYMLINK:
      return "symlink";
    case BPFJ_FS_REASON_MKDIR:
      return "mkdir";
    case BPFJ_FS_REASON_SETATTR:
      return "setattr";
    case BPFJ_FS_REASON_GETATTR:
      return "getattr";
    case BPFJ_FS_REASON_SETXATTR:
      return "setxattr";
    case BPFJ_FS_REASON_GETXATTR:
      return "getxattr";
    case BPFJ_FS_REASON_LISTXATTR:
      return "listxattr";
    case BPFJ_FS_REASON_REMOVEXATTR:
      return "removexattr";
    case BPFJ_FS_REASON_CREATE:
      return "create";
    default:
      return nullptr;
  }
}

[[nodiscard]] const char* fsTraceTokenToString(__u8 token) noexcept {
  switch (token) {
    case BPFJ_FS_TRACE_MATCH:
      return "match";
    case BPFJ_FS_TRACE_NO_MATCH:
      return "no_match";
    case BPFJ_FS_TRACE_PERM_DENY:
      return "perm_deny";
    case BPFJ_FS_TRACE_TOO_DEEP:
      return "too_deep";
    case BPFJ_FS_TRACE_MATCH_ERROR:
      return "match_error";
    case BPFJ_FS_TRACE_EXDEV_DENY:
      return "exdev_deny";
    default:
      return nullptr;
  }
}

[[nodiscard]] std::string decodeFsTrace(const struct bpfj_event& entry) {
  const auto& trace = entry.fs_trace;
  if (entry.type != BPFJ_EVENT_FS || trace.version != BPFJ_FS_TRACE_VERSION ||
      trace.len == 0 || trace.len > BPFJ_FS_TRACE_MAX_TOKENS) {
    return {};
  }

  const char* prefix = fsReasonTracePrefix(trace.reason);
  if (!prefix) {
    return {};
  }

  std::string decoded(prefix);
  for (__u8 i = 0; i < trace.len; ++i) {
    const __u8 token = (trace.tokens >> (i * 8)) & 0xff;
    const char* text = fsTraceTokenToString(token);
    if (!text) {
      return {};
    }
    decoded.push_back('>');
    decoded.append(text);
  }
  return decoded;
}

} // namespace

std::string eventTypeName(int type) {
  switch (type) {
    case BPFJ_EVENT_JAILER:
      return "jailer";
    case BPFJ_EVENT_ENROLL:
      return "enroll";
    case BPFJ_EVENT_VERITY:
      return "verity";
    case BPFJ_EVENT_KILL:
      return "kill";
    case BPFJ_EVENT_PTRACE:
      return "ptrace";
    case BPFJ_EVENT_BPF:
      return "bpf";
    case BPFJ_EVENT_LKM:
      return "lkm";
    case BPFJ_EVENT_FS:
      return "fs";
    case BPFJ_EVENT_UNIX:
      return "unix";
    case BPFJ_EVENT_MOUNT:
      return "mount";
    case BPFJ_EVENT_PROC:
      return "proc";
    case BPFJ_EVENT_EXEC:
      return "exec";
    default:
      return "unknown(" + std::to_string(type) + ")";
  }
}

std::string severityName(int severity) {
  switch (severity) {
    case BPFJ_SEV_NONE:
      return "none";
    case BPFJ_SEV_FATAL:
      return "fatal";
    case BPFJ_SEV_WARNING:
      return "warning";
    case BPFJ_SEV_INFO:
      return "info";
    default:
      return "unknown(" + std::to_string(severity) + ")";
  }
}

std::string formatBpfLog(const struct bpfj_log& entry) {
  const auto file = boundedString(entry.file, sizeof(entry.file));
  const auto msg = boundedString(entry.msg, sizeof(entry.msg));

  std::string line = "BPF Message: ";
  line += file;
  line += ":";
  line += std::to_string(entry.line);
  line += ": sev=";
  line += severityName(entry.severity);
  line += " code=";
  line += std::to_string(entry.code);
  line += " cpu=";
  line += std::to_string(entry.cpu);
  line += ": ";
  line += msg;
  return line;
}

std::string formatBpfEvent(const struct bpfj_event& entry) {
  char uuid[sizeof("00000000-0000-0000-0000-000000000000")];
  std::snprintf(
      uuid,
      sizeof(uuid),
      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      entry.pod.uuid.uuid[0],
      entry.pod.uuid.uuid[1],
      entry.pod.uuid.uuid[2],
      entry.pod.uuid.uuid[3],
      entry.pod.uuid.uuid[4],
      entry.pod.uuid.uuid[5],
      entry.pod.uuid.uuid[6],
      entry.pod.uuid.uuid[7],
      entry.pod.uuid.uuid[8],
      entry.pod.uuid.uuid[9],
      entry.pod.uuid.uuid[10],
      entry.pod.uuid.uuid[11],
      entry.pod.uuid.uuid[12],
      entry.pod.uuid.uuid[13],
      entry.pod.uuid.uuid[14],
      entry.pod.uuid.uuid[15]);

  std::string line = "event";
  line += " type=";
  line += eventTypeName(entry.type);
  line += " pid=";
  line += std::to_string(entry.pid);
  line += " tid=";
  line += std::to_string(entry.tid);
  line += " ts_ns=";
  line += std::to_string(entry.timestamp_ns);
  line += " role=";
  line += boundedString(entry.pod.role_id.id, sizeof(entry.pod.role_id.id));
  line += " pod_id=";
  line += boundedString(entry.pod.pod_id.id, sizeof(entry.pod.pod_id.id));
  line += " uuid=";
  line += uuid;
  line += " refs=";
  line += std::to_string(entry.pod.refs);
  line += " creation_ns=";
  line += std::to_string(entry.pod.creation_time_ns);
  line += " gc_attempts=";
  line += std::to_string(entry.pod.gc_removal_attempts);
  line += " enrollment_source=";
  line += std::to_string(entry.pod.enrollment_source);
  const std::string fsTrace = decodeFsTrace(entry);
  if (!fsTrace.empty()) {
    line += " fs_trace=";
    line += fsTrace;
  }
  return line;
}

Expected<std::string> formatBpfLog(const void* data, std::size_t size) {
  if (data == nullptr) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "bpf log record was null"));
  }

  if (size < sizeof(struct bpfj_log)) {
    return makeUnexpected(makeError(
        std::errc::argument_out_of_domain,
        "bpf log record was ",
        std::to_string(size),
        " bytes, expected at least ",
        std::to_string(sizeof(struct bpfj_log))));
  }

  return formatBpfLog(*static_cast<const struct bpfj_log*>(data));
}

Expected<std::string> formatBpfEvent(const void* data, std::size_t size) {
  if (data == nullptr) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "bpf event record was null"));
  }

  constexpr std::size_t kBaseEventSize = offsetof(struct bpfj_event, fs_trace);
  if (size < kBaseEventSize) {
    return makeUnexpected(makeError(
        std::errc::argument_out_of_domain,
        "bpf event record was ",
        std::to_string(size),
        " bytes, expected at least ",
        std::to_string(kBaseEventSize)));
  }

  struct bpfj_event entry{};
  std::memcpy(&entry, data, std::min(size, sizeof(entry)));
  return formatBpfEvent(entry);
}

} // namespace bpfjailer::log
