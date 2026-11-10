// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#define POD_UUID_LEN 37
#define BPFJ_UUID_BYTES 16

struct bpfj_uuid {
  unsigned char uuid[BPFJ_UUID_BYTES];
};
