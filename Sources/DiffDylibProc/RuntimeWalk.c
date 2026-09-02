#include "DiffDylibProc.h"

#include <errno.h>
#include <libproc.h>
#include <mach/vm_prot.h>
#include <string.h>
#include <sys/proc_info.h>

int diffdylib_list_executable_mappings(
    pid_t pid,
    diffdylib_mapping_t *out,
    int capacity
) {
    if (pid <= 0 || out == NULL || capacity <= 0) {
        errno = EINVAL;
        return -1;
    }

    struct proc_regionwithpathinfo region;
    uint64_t addr = 0;
    int written = 0;
    int iterations = 0;

    memset(&region, 0, sizeof(region));
    while (iterations++ < 100000) {
        int ret = proc_pidinfo(
            pid,
            PROC_PIDREGIONPATHINFO,
            addr,
            &region,
            (int)PROC_PIDREGIONPATHINFO_SIZE
        );
        if (ret == 0) {
            break;
        }
        if (ret != (int)PROC_PIDREGIONPATHINFO_SIZE) {
            if (written == 0 && errno == 0) {
                errno = EPERM;
            }
            return written > 0 ? written : -1;
        }

        if ((region.prp_prinfo.pri_protection & VM_PROT_EXECUTE) != 0
            && region.prp_vip.vip_path[0] != '\0'
            && written < capacity) {
            memset(&out[written], 0, sizeof(out[written]));
            strncpy(
                out[written].path,
                region.prp_vip.vip_path,
                DIFFDYLIB_MAPPING_PATH_MAX - 1
            );
            out[written].address = region.prp_prinfo.pri_address;
            out[written].size = region.prp_prinfo.pri_size;
            written++;
        }

        uint64_t size = region.prp_prinfo.pri_size;
        uint64_t next = region.prp_prinfo.pri_address + (size == 0 ? 0x1000 : size);
        if (next <= addr) {
            break;
        }
        addr = next;
        memset(&region, 0, sizeof(region));
    }

    return written;
}

int diffdylib_pid_path(pid_t pid, char *buffer, unsigned int size) {
    if (pid <= 0 || buffer == NULL || size == 0) {
        errno = EINVAL;
        return -1;
    }
    memset(buffer, 0, size);
    return proc_pidpath(pid, buffer, size);
}
