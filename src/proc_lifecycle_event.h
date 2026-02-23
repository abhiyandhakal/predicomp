#ifndef PROC_LIFECYCLE_EVENT_H
#define PROC_LIFECYCLE_EVENT_H

#ifdef __VMLINUX_H__
typedef __u32 proc_evt_u32;
typedef __u64 proc_evt_u64;
#else
#include <stdint.h>
typedef uint32_t proc_evt_u32;
typedef uint64_t proc_evt_u64;
#endif

#define PROC_LIFECYCLE_COMM_LEN 16

enum proc_lifecycle_event_type {
    PROC_LIFECYCLE_EVENT_EXEC = 1,
    PROC_LIFECYCLE_EVENT_EXIT = 2,
    PROC_LIFECYCLE_EVENT_FORK = 3,
};

struct proc_lifecycle_event {
    proc_evt_u32 type;
    proc_evt_u32 pid;
    proc_evt_u32 tgid;
    proc_evt_u32 ppid;
    proc_evt_u64 ktime_ns;
    char comm[PROC_LIFECYCLE_COMM_LEN];
};

#endif
