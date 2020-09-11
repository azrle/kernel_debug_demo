#include<linux/module.h>
#include<linux/version.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/kprobes.h>
#include<net/tcp.h>

MODULE_AUTHOR("Xuanzhong Wei");
MODULE_DESCRIPTION("Probe for summing the number of packets marked as lost");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
 
int jprobe_tcp_sum_lost_entry(struct tcp_sock *tp, struct sk_buff *skb) {
    printk(
        "packets marked as lost: {cur: %d, incr: %d}",
        tp->lost, tcp_skb_pcount(skb)
    );

    jprobe_return();
    return 0;
}
 
static struct jprobe jprobe_tcp_sum_lost = {
    .kp = {
        .symbol_name = "tcp_sum_lost",
    },
    .entry = jprobe_tcp_sum_lost_entry,
};
 
static __init int jprobe_tcp_sum_lost_init(void)
{
    register_jprobe(&jprobe_tcp_sum_lost);
    printk("jprobe_tcp_sum_lost installed\n");
    return 0;
}
 
static __exit void jprobe_tcp_sum_lost_exit(void)
{
    unregister_jprobe(&jprobe_tcp_sum_lost);
    printk("jprobe_tcp_sum_lost removed\n");
}
 
module_init(jprobe_tcp_sum_lost_init);
module_exit(jprobe_tcp_sum_lost_exit);
