// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#define BPFJ_FS_MODE_READ 0x1U
#define BPFJ_FS_MODE_WRITE 0x2U

#define BPFJ_FS_TRACE_VERSION 1
#define BPFJ_FS_TRACE_MAX_TOKENS 8

// Stable operation identifiers carried by filesystem events. Values align with
// the internal FS2 reasons where the operations overlap.
enum bpfj_fs_reason {
  BPFJ_FS_REASON_OPEN = 0,
  BPFJ_FS_REASON_UNLINK = 1,
  BPFJ_FS_REASON_LINK_OLD = 2,
  BPFJ_FS_REASON_LINK_NEW = 3,
  BPFJ_FS_REASON_MKNOD = 4,
  BPFJ_FS_REASON_RENAME_OLD = 5,
  BPFJ_FS_REASON_RENAME_NEW = 6,
  BPFJ_FS_REASON_RMDIR = 8,
  BPFJ_FS_REASON_SYMLINK = 11,
  BPFJ_FS_REASON_MKDIR = 12,
  BPFJ_FS_REASON_SETATTR = 14,
  BPFJ_FS_REASON_GETATTR = 15,
  BPFJ_FS_REASON_SETXATTR = 16,
  BPFJ_FS_REASON_GETXATTR = 17,
  BPFJ_FS_REASON_LISTXATTR = 18,
  BPFJ_FS_REASON_REMOVEXATTR = 19,
  BPFJ_FS_REASON_CREATE = 21,
};

// Stable decision tokens. MATCH marks entry into policy matching, not a
// successful rule match; the following token records the terminal outcome.
// Append new values rather than renumbering existing ones.
enum bpfj_fs_trace_token {
  BPFJ_FS_TRACE_MATCH = 1,
  BPFJ_FS_TRACE_NO_MATCH = 2,
  BPFJ_FS_TRACE_PERM_DENY = 4,
  BPFJ_FS_TRACE_TOO_DEEP = 5,
  BPFJ_FS_TRACE_MATCH_ERROR = 7,
  BPFJ_FS_TRACE_EXDEV_DENY = 15,
};

struct bpfj_fs_path_entry {
  __u32 mode;
};
