#include<linux/module.h>
#include<linux/version.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/kprobes.h>
#include<net/ip.h>

MODULE_AUTHOR("Xuanzhong Wei");
MODULE_DESCRIPTION("IP receive routine probe");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
 
int jprobe_ip_rcv_entry(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    const struct iphdr *iph;
    if (skb && pskb_may_pull(skb, sizeof(struct iphdr))) {
        iph = ip_hdr(skb);
        printk("pkt recv: %pI4 -> %pI4\n", &iph->saddr, &iph->daddr);
    }
    jprobe_return();
    return 0;
}
 
static struct jprobe jprobe_ip_rcv = {
    .kp = {
        .symbol_name = "ip_rcv",
    },
    .entry = jprobe_ip_rcv_entry,
};
 
static __init int jprobe_ip_rcv_init(void)
{
    register_jprobe(&jprobe_ip_rcv);
    return 0;
}
 
static __exit void jprobe_ip_rcv_exit(void)
{
    unregister_jprobe(&jprobe_ip_rcv);
    printk("jprobe_ip_rcv removed\n");
}
 
module_init(jprobe_ip_rcv_init);
module_exit(jprobe_ip_rcv_exit);
