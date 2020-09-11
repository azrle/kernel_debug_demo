#include<linux/module.h>
#include<linux/version.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/kprobes.h>
#include<net/tcp.h>

MODULE_AUTHOR("Xuanzhong Wei");
MODULE_DESCRIPTION("TCP retransmit timeout handler probe");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

/* include/net/tcp_states.h */
const char* TCP_STATE_NAME[14] = {
    "UNKNOWN",
    "TCP_ESTABLISHED",
    "TCP_SYN_SENT",
    "TCP_SYN_RECV",
    "TCP_FIN_WAIT1",
    "TCP_FIN_WAIT2",
    "TCP_TIME_WAIT",
    "TCP_CLOSE",
    "TCP_CLOSE_WAIT",
    "TCP_LAST_ACK",
    "TCP_LISTEN",
    "TCP_CLOSING",
    "TCP_NEW_SYN_RECV",
    "TCP_MAX_STATES"
};
 
int jprobe_tcp_fastretrans_alert_entry(struct sock *sk, const int acked, bool is_dupack, int *ack_flag, int *rexmit) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct inet_sock *inet = inet_sk(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    do {
        if (!tp->packets_out) break;

        if (sk->sk_family != AF_INET) break; /* IPv4 Only */

        printk(
            "\"fast-retransmit%s\":{"
            "\"jiffies\":%u,\"rcv_tstamp\":%u,\"lsndtime\":%u,\"srtt_us\":%u,"
            "\"peer\":\"%pI4:%u/%u\",\"state\":%s,"
            "\"snd_una\":%u,\"snd_nxt\":%u,\"snd_wnd\":%u,"
            "\"segs_out\":%u,\"delivered\":%u,\"lost\":%u,"
            "\"packets_out\":%u,\"retrans_out\":%u,\"lost_out\":%u,\"sacked_out\":%u,"
            "\"icsk\":{"
            "\"rto\":%u,\"ca_state\":%u,"
            "\"retransmits\":%u,\"backoff\":%u"
            "}}\n", 
            tp->fastopen_rsk?"[fastopen]":"",
            tcp_jiffies32, tp->rcv_tstamp, tp->lsndtime, tp->srtt_us,
            &inet->inet_daddr, ntohs(inet->inet_dport), inet->inet_num,
            sk->sk_state<14?TCP_STATE_NAME[sk->sk_state]:"UNKNOWN",
            tp->snd_una, tp->snd_nxt, tp->snd_wnd,
            tp->segs_out, tp->delivered, tp->lost,
            tp->packets_out, tp->retrans_out, tp->lost_out, tp->sacked_out,
            icsk->icsk_rto, icsk->icsk_ca_state,
            icsk->icsk_retransmits, icsk->icsk_backoff
        );
    } while (0);

    jprobe_return();
    return 0;
}
 
static struct jprobe jprobe_tcp_fastretrans_alert = {
    .kp = {
        .symbol_name = "tcp_fastretrans_alert",
    },
    .entry = jprobe_tcp_fastretrans_alert_entry,
};
 
static __init int jprobe_tcp_fastretrans_alert_init(void)
{
    register_jprobe(&jprobe_tcp_fastretrans_alert);
    printk("jprobe_tcp_fastretrans_alert installed\n");
    return 0;
}
 
static __exit void jprobe_tcp_fastretrans_alert_exit(void)
{
    unregister_jprobe(&jprobe_tcp_fastretrans_alert);
    printk("jprobe_tcp_fastretrans_alert removed\n");
}
 
module_init(jprobe_tcp_fastretrans_alert_init);
module_exit(jprobe_tcp_fastretrans_alert_exit);
