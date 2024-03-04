/* SPDX-License-Identifier: GPL-2.0-only */
/* OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2024 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNPEER_H_
#define _NET_OVPN_OVPNPEER_H_

#include <net/dst_cache.h>
#include <net/strparser.h>
#include <uapi/linux/ovpn.h>

#include "bind.h"
#include "pktid.h"
#include "crypto.h"
#include "socket.h"
#include "stats.h"

#include <net/dst_cache.h>
#include <uapi/linux/ovpn.h>

/**
 * struct ovpn_peer - the main remote peer object
 * @ovpn: main openvpn instance this peer belongs to
 * @id: unique identifier
 * @vpn_addrs: IP addresses assigned over the tunnel
 * @vpn_addrs.ipv4: IPv4 assigned to peer on the tunnel
 * @vpn_addrs.ipv6: IPv6 assigned to peer on the tunnel
 * @hash_entry_id: entry in the peer ID hashtable
 * @hash_entry_addr4: entry in the peer IPv4 hashtable
 * @hash_entry_addr6: entry in the peer IPv6 hashtable
 * @hash_entry_transp_addr: entry in the peer transport address hashtable
 * @sock: the socket being used to talk to this peer
 * @tcp: keeps track of TCP specific state
 * @tcp.strp: stream parser context (TCP only)
 * @tcp.tx_work: work for deferring outgoing packet processing (TCP only)
 * @tcp.user_queue: received packets that have to go to userspace (TCP only)
 * @tcp.tx_in_progress: true if TX is already ongoing (TCP only)
 * @tcp.out_msg.skb: packet scheduled for sending (TCP only)
 * @tcp.out_msg.offset: offset where next send should start (TCP only)
 * @tcp.out_msg.len: remaining data to send within packet (TCP only)
 * @tcp.sk_cb.sk_data_ready: pointer to original cb (TCP only)
 * @tcp.sk_cb.sk_write_space: pointer to original cb (TCP only)
 * @tcp.sk_cb.prot: pointer to original prot object (TCP only)
 * @tcp.sk_cb.ops: pointer to the original prot_ops object (TCP only)
 * @crypto: the crypto configuration (ciphers, keys, etc..)
 * @dst_cache: cache for dst_entry used to send to peer
 * @bind: remote peer binding
 * @keepalive_xmit: timer used to send the next keepalive
 * @keepalive_interval: seconds after which a new keepalive should be sent
 * @keepalive_recv: timer used to check for received keepalives
 * @keepalive_timeout: seconds after which an inactive peer is considered dead
 * @halt: true if ovpn_peer_mark_delete was called
 * @vpn_stats: per-peer in-VPN TX/RX stays
 * @link_stats: per-peer link/transport TX/RX stats
 * @delete_reason: why peer was deleted (i.e. timeout, transport error, ..)
 * @lock: protects binding to peer (bind)
 * @refcount: reference counter
 * @rcu: used to free peer in an RCU safe way
 * @delete_work: deferred cleanup work, used to notify userspace
 */
struct ovpn_peer {
	struct ovpn_struct *ovpn;
	u32 id;
	struct {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} vpn_addrs;
	struct hlist_node hash_entry_id;
	struct hlist_node hash_entry_addr4;
	struct hlist_node hash_entry_addr6;
	struct hlist_node hash_entry_transp_addr;
	struct ovpn_socket *sock;

	/* state of the TCP reading. Needed to keep track of how much of a
	 * single packet has already been read from the stream and how much is
	 * missing
	 */
	struct {
		struct strparser strp;
		struct work_struct tx_work;
		struct sk_buff_head user_queue;
		bool tx_in_progress;

		struct {
			struct sk_buff *skb;
			int offset;
			int len;
		} out_msg;

		struct {
			void (*sk_data_ready)(struct sock *sk);
			void (*sk_write_space)(struct sock *sk);
			struct proto *prot;
			const struct proto_ops *ops;
		} sk_cb;
	} tcp;
	struct ovpn_crypto_state crypto;
	struct dst_cache dst_cache;
	struct ovpn_bind __rcu *bind;
	struct timer_list keepalive_xmit;
	unsigned long keepalive_interval;
	struct timer_list keepalive_recv;
	unsigned long keepalive_timeout;
	bool halt;
	struct ovpn_peer_stats vpn_stats;
	struct ovpn_peer_stats link_stats;
	enum ovpn_del_peer_reason delete_reason;
	spinlock_t lock; /* protects bind */
	struct kref refcount;
	struct rcu_head rcu;
	struct work_struct delete_work;
};

/**
 * ovpn_peer_hold - increase reference counter
 * @peer: the peer whose counter should be increased
 *
 * Return: true if the counter was increased or false if it was zero already
 */
static inline bool ovpn_peer_hold(struct ovpn_peer *peer)
{
	return kref_get_unless_zero(&peer->refcount);
}

void ovpn_peer_release(struct ovpn_peer *peer);
void ovpn_peer_release_kref(struct kref *kref);

/**
 * ovpn_peer_put - decrease reference counter
 * @peer: the peer whose counter should be decreased
 */
static inline void ovpn_peer_put(struct ovpn_peer *peer)
{
	kref_put(&peer->refcount, ovpn_peer_release_kref);
}

struct ovpn_peer *ovpn_peer_new(struct ovpn_struct *ovpn, u32 id);
int ovpn_peer_add(struct ovpn_struct *ovpn, struct ovpn_peer *peer);
int ovpn_peer_del(struct ovpn_peer *peer, enum ovpn_del_peer_reason reason);
void ovpn_peer_release_p2p(struct ovpn_struct *ovpn);
void ovpn_peers_free(struct ovpn_struct *ovpn);

struct ovpn_peer *ovpn_peer_get_by_transp_addr(struct ovpn_struct *ovpn,
					       struct sk_buff *skb);
struct ovpn_peer *ovpn_peer_get_by_id(struct ovpn_struct *ovpn, u32 peer_id);
struct ovpn_peer *ovpn_peer_get_by_dst(struct ovpn_struct *ovpn,
				       struct sk_buff *skb);
bool ovpn_peer_check_by_src(struct ovpn_struct *ovpn, struct sk_buff *skb,
			    struct ovpn_peer *peer);

/**
 * ovpn_peer_keepalive_recv_reset - reset keepalive timeout
 * @peer: peer for which the timeout should be reset
 *
 * To be invoked upon reception of an authenticated packet from peer in order
 * to report valid activity and thus reset the keepalive timeout
 */
static inline void ovpn_peer_keepalive_recv_reset(struct ovpn_peer *peer)
{
	u32 delta = msecs_to_jiffies(peer->keepalive_timeout * MSEC_PER_SEC);

	if (unlikely(!delta))
		return;

	mod_timer(&peer->keepalive_recv, jiffies + delta);
}

/**
 * ovpn_peer_keepalive_xmit_reset - reset keepalive sending timer
 * @peer: peer for which the timer should be reset
 *
 * To be invoked upon sending of an authenticated packet to peer in order
 * to report valid outgoing activity and thus reset the keepalive sending
 * timer
 */
static inline void ovpn_peer_keepalive_xmit_reset(struct ovpn_peer *peer)
{
	u32 delta = msecs_to_jiffies(peer->keepalive_interval * MSEC_PER_SEC);

	if (unlikely(!delta))
		return;

	mod_timer(&peer->keepalive_xmit, jiffies + delta);
}

void ovpn_peer_keepalive_set(struct ovpn_peer *peer, u32 interval, u32 timeout);

void ovpn_peer_update_local_endpoint(struct ovpn_peer *peer,
				     struct sk_buff *skb);

void ovpn_peer_float(struct ovpn_peer *peer, struct sk_buff *skb);
int ovpn_peer_reset_sockaddr(struct ovpn_peer *peer,
			     const struct sockaddr_storage *ss,
			     const u8 *local_ip);

#endif /* _NET_OVPN_OVPNPEER_H_ */
