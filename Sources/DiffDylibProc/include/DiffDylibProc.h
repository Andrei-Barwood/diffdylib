#ifndef DIFFDYLIB_PROC_H
#define DIFFDYLIB_PROC_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIFFDYLIB_MAPPING_PATH_MAX 1024
#define DIFFDYLIB_MAX_MAPPINGS 4096

typedef struct diffdylib_mapping {
    char path[DIFFDYLIB_MAPPING_PATH_MAX];
    uint64_t address;
    uint64_t size;
} diffdylib_mapping_t;

/// Walk VM regions of `pid` via proc_pidinfo(PROC_PIDREGIONPATHINFO).
/// Records file-backed executable mappings (VM_PROT_EXECUTE + non-empty path).
/// Does not call task_for_pid and does not read the target's address space.
///
/// Returns the number of mappings written (capped at `capacity`), or -1 on error
/// with errno set.
int diffdylib_list_executable_mappings(
    pid_t pid,
    diffdylib_mapping_t *out,
    int capacity
);

/// proc_pidpath wrapper. Returns bytes written, or -1 on error.
int diffdylib_pid_path(pid_t pid, char *buffer, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif
