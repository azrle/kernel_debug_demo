#include<linux/module.h>
#include<linux/version.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/kprobes.h>
#include<linux/dcache.h>

MODULE_AUTHOR("Xuanzhong Wei");
MODULE_DESCRIPTION("Probe for dentry_kill");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

int jprobe_dentry_kill_entry(struct dentry *dentry) {
    char buf[256], *path;
    const char *fs_type;
    fs_type = dentry->d_sb->s_type->name;
    if (strcmp(fs_type, "ext4") == 0 || strcmp(fs_type, "xfs") == 0) {
        path = dentry_path_raw(dentry, buf, 256);
        printk("%s(%d) __dentry_kill %s %s", current->comm, current->pid, path, dentry->d_inode ? "":"(negative)");
    }

    jprobe_return();
    return 0;
}

static struct jprobe jprobe_dentry_kill = {
    .kp = {
        .symbol_name = "__dentry_kill",
    },
    .entry = jprobe_dentry_kill_entry,
};

static __init int jprobe_dentry_kill_init(void)
{
    register_jprobe(&jprobe_dentry_kill);
    printk("jprobe_dentry_kill installed\n");
    return 0;
}

static __exit void jprobe_dentry_kill_exit(void)
{
    unregister_jprobe(&jprobe_dentry_kill);
    printk("jprobe_dentry_kill removed\n");
}

module_init(jprobe_dentry_kill_init);
module_exit(jprobe_dentry_kill_exit);
