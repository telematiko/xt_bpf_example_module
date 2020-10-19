#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/if_tunnel.h>
#include <uapi/linux/mpls.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"
#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF
#define PAYLOAD_HEAD	48

#define PROG(F) SEC("socket/"__stringify(F)) int bpf_func_##F

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 8);
} jmp_table SEC(".maps");

#define PARSE_IP 3

static inline void parse_eth_proto(struct __sk_buff *skb, u32 proto)
{
	switch (proto) {
	case ETH_P_IP:
		bpf_tail_call(skb, &jmp_table, PARSE_IP);
		break;
	}
}

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct flow_key_record {
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
	__u32 h_proto;
	__u32 packet_len;
	__u16 payload_len;
	__u8 payload[PAYLOAD_HEAD]; // in our case we get only first 48 bytes from packet payload
};

static inline int ip_is_fragment(struct __sk_buff *ctx, __u64 nhoff)
{
	return load_half(ctx, nhoff + offsetof(struct iphdr, frag_off))
		& (IP_MF | IP_OFFSET);
}

static inline __u32 ipv6_addr_hash(struct __sk_buff *ctx, __u64 off)
{
	__u64 w0 = load_word(ctx, off);
	__u64 w1 = load_word(ctx, off + 4);
	__u64 w2 = load_word(ctx, off + 8);
	__u64 w3 = load_word(ctx, off + 12);

	return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

struct globals {
	struct flow_key_record flow;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct globals);
	__uint(max_entries, 32);
} percpu_map SEC(".maps");

/* user poor man's per_cpu until native support is ready */
static struct globals *this_cpu_globals(void)
{
	u32 key = bpf_get_smp_processor_id();

	return bpf_map_lookup_elem(&percpu_map, &key);
}

/* some simple stats for user space consumption */
struct pair {
	__u64 packets;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct flow_key_record);
	__type(value, struct pair);
	__uint(max_entries, 1024);
} hash_map SEC(".maps");

static void update_stats(struct __sk_buff *skb, struct globals *g)
{
	struct flow_key_record key = g->flow;
	struct pair *value;

	value = bpf_map_lookup_elem(&hash_map, &key);
	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, skb->len);
	} else {
		struct pair val = {1, skb->len};

		bpf_map_update_elem(&hash_map, &key, &val, BPF_ANY);
	}
}

static __always_inline void parse_ip_proto(struct __sk_buff *skb,
					   struct globals *g, __u32 ip_proto)
{
	__u32 nhoff = skb->cb[0];
	int poff;

	__u32 packet_data_offset = 0;
	__u32 ihl = 0;

	switch (ip_proto) {
	case IPPROTO_IPIP:
		parse_eth_proto(skb, ETH_P_IP);
		break;

	case IPPROTO_TCP:
		g->flow.ports = load_word(skb, nhoff);
		__u8 tcp_h_len_byte = load_byte(skb, nhoff + offsetof(struct tcphdr, ack_seq) + 4/*sizeof ack_seq*/);
		__u8 tcp_h_len = (tcp_h_len_byte &  0xF0) >> 2;

		ihl = skb->cb[4];
		g->flow.payload_len = g->flow.packet_len - ihl - tcp_h_len;

		packet_data_offset = ETH_HLEN + ihl + tcp_h_len;


		if (g->flow.payload_len > 0) {
			for (int i = 0; i < PAYLOAD_HEAD; i++) {
				g->flow.payload[i] = 0;
			}
			for (int i = 0; i < PAYLOAD_HEAD; i++) {
				bpf_skb_load_bytes_relative(skb, packet_data_offset + i, &g->flow.payload[i], 1, BPF_HDR_START_MAC);
				if (i + 1 == g->flow.payload_len)
				  break;
			}
		}

		g->flow.ip_proto = ip_proto;
		update_stats(skb, g);


		/*
		 *
		 * at this point we can call matching function to determine iptables action with current TCP packet.
		 *
		 * */

		break;

	case IPPROTO_UDP:
		g->flow.ports = load_word(skb, nhoff);
		__u8 udph_len = sizeof(struct udphdr);
		ihl = skb->cb[4];

		g->flow.payload_len = load_half(skb, nhoff + offsetof(struct udphdr, len));

		packet_data_offset = ETH_HLEN + ihl + udph_len;

		if (g->flow.payload_len > 0) {
			for (int i = 0; i < PAYLOAD_HEAD; i++) {
				g->flow.payload[i] = 0;
			}

			for (int i = 0; i < PAYLOAD_HEAD; i++) {
				bpf_skb_load_bytes_relative(skb, packet_data_offset + i, &g->flow.payload[i], 1, BPF_HDR_START_MAC);
				if (i + 1 == g->flow.payload_len)
				  break;
			}
		}

		g->flow.ip_proto = ip_proto;
		update_stats(skb, g);

		/*
		 *
                 * at this point we can call matching function to determine iptables action with current UDP packet.
		 *
                 * */

		break;

	default:
		break;
	}

}

PROG(PARSE_IP)(struct __sk_buff *skb)
{
	struct globals *g = this_cpu_globals();
	__u32 nhoff, verlen, ip_proto;

	if (!g)
		return 0;

	nhoff = skb->cb[0];

	if (unlikely(ip_is_fragment(skb, nhoff)))
		return 0;

	ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));

	if (ip_proto != IPPROTO_GRE) {
		g->flow.src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
		g->flow.dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
		g->flow.h_proto = load_half(skb, offsetof(struct ethhdr, h_proto)); // ?
		g->flow.packet_len = load_half(skb, nhoff + offsetof(struct iphdr, tot_len)); // +
	}

	verlen = load_byte(skb, nhoff + 0/*offsetof(struct iphdr, ihl)*/);
	__u32 ihl = (verlen & 0xF) << 2;
	nhoff += ihl;

	skb->cb[0] = nhoff;
	skb->cb[4] = ihl;
	parse_ip_proto(skb, g, ip_proto);
	return 0;
}


SEC("socket/0")
int main_prog(struct __sk_buff *skb)
{
	__u32 nhoff = ETH_HLEN;
	__u32 proto = load_half(skb, 12);

	skb->cb[0] = nhoff;
	parse_eth_proto(skb, proto);
	return 0;
}

char _license[] SEC("license") = "GPL";
