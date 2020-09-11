from __future__ import print_function
from bcc import BPF
from os import getpid

# load BPF program
bpf_text = """
#define MAX_BUF_SIZE 128
#define PARENT_DIR_SIZE 64
#define FS_TYPE_SIZE 8

#include <linux/fs.h>

int trace_dentry(struct pt_regs *ctx, struct dentry *dentry) {
    if (dentry->d_parent == NULL || dentry->d_parent == dentry)
        return 0;

    // if (!dentry->d_sb || dentry->d_sb->s_type->name[0] != 'e')

    unsigned char path[MAX_BUF_SIZE] = {};
    bpf_probe_read_str(path, sizeof(path), dentry->d_sb->s_type->name);

    struct qstr d_name;
    bpf_probe_read(&d_name, sizeof(d_name), &dentry->d_name);
    bpf_probe_read(&path[PARENT_DIR_SIZE], MAX_BUF_SIZE-PARENT_DIR_SIZE, d_name.name);

    struct dentry *orig = dentry;
    if (dentry->d_parent && dentry->d_parent != dentry) {
        dentry = dentry->d_parent;
        bpf_probe_read(&d_name, sizeof(d_name), &dentry->d_name);
        bpf_probe_read(&path[FS_TYPE_SIZE], PARENT_DIR_SIZE - FS_TYPE_SIZE, d_name.name);
        if (path[FS_TYPE_SIZE] == '/' && !path[FS_TYPE_SIZE+1])
            path[FS_TYPE_SIZE] = 0;
    }

    u16 i, j = 0;
#pragma clang loop unroll(full)
    for (i=0;i<FS_TYPE_SIZE-1 && path[i];i++) {
        j = i+1;
    }
    path[j++] = ':';
#pragma clang loop unroll(full)
    for (i=FS_TYPE_SIZE;i<PARENT_DIR_SIZE-1 && path[i];i++) {
        path[j++] = path[i];
    }
    path[j++] = '/';
#pragma clang loop unroll(full)
    for (i=PARENT_DIR_SIZE;i<MAX_BUF_SIZE-1 && path[i];i++) {
        path[j++] = path[i];
    }
    path[j] = '\\0';

    bpf_trace_printk("negative:%d\tpath:%s\\n", orig->d_inode?0:1, path);

    return 0;
};
"""
b = BPF(text=bpf_text)
b.attach_kprobe(event="__dentry_kill", fn_name="trace_dentry")

me = getpid()
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    if pid == me or msg == "":
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
