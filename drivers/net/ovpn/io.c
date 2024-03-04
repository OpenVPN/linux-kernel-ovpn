// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2024 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/gro_cells.h>
#include <net/gso.h>
#include <net/ip.h>

#include "ovpnstruct.h"
#include "peer.h"
#include "io.h"
#include "crypto.h"
#include "crypto_aead.h"
#include "netlink.h"
#include "proto.h"
#include "socket.h"
#include "udp.h"
#include "skb.h"

/* Called after decrypt to write the IP packet to the device.
 * This method is expected to manage/free the skb.
 */
static void ovpn_netdev_write(struct ovpn_peer *peer, struct sk_buff *skb)
{
	/* packet integrity was verified on the VPN layer - no need to perform
	 * any additional check along the stack
	 */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum_level = ~0;

	/* skb hash for transport packet no longer valid after decapsulation */
	skb_clear_hash(skb);

	/* post-decrypt scrub -- prepare to inject encapsulated packet onto the
	 * interface, based on __skb_tunnel_rx() in dst.h
	 */
	skb->dev = peer->ovpn->dev;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, true);

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_probe_transport_header(skb);
	skb_reset_inner_headers(skb);

	memset(skb->cb, 0, sizeof(skb->cb));

	/* cause packet to be "received" by the interface */
	if (likely(gro_cells_receive(&peer->ovpn->gro_cells,
				     skb) == NET_RX_SUCCESS))
		/* update RX stats with the size of decrypted packet */
		dev_sw_netstats_rx_add(peer->ovpn->dev, skb->len);
	else
		dev_core_stats_rx_dropped_inc(peer->ovpn->dev);
}

void ovpn_decrypt_post(struct sk_buff *skb, int ret)
{
	struct ovpn_crypto_key_slot *ks = ovpn_skb_cb(skb)->ks;
	struct ovpn_peer *peer = ovpn_skb_cb(skb)->peer;
	__be16 proto;
	__be32 *pid;

	/* crypto is happening asyncronously. this function will be called
	 * again later by the crypto callback with a proper return code
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	if (unlikely(ret < 0)) {
		net_err_ratelimited("%s: error during decryption for peer %u, key-id %u: %d\n",
				    peer->ovpn->dev->name, peer->id, ks->key_id,
				    ret);
		goto drop;
	}

	/* PID sits after the op */
	pid = (__force __be32 *)(skb->data + OVPN_OP_SIZE_V2);
	ret = ovpn_pktid_recv(&ks->pid_recv, ntohl(*pid), 0);
	if (unlikely(ret < 0))
		goto drop;

	/* point to encapsulated IP packet */
	__skb_pull(skb, ovpn_skb_cb(skb)->payload_offset);

	/* check if this is a valid datapacket that has to be delivered to the
	 * ovpn interface
	 */
	skb_reset_network_header(skb);
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto)) {
		/* check if null packet */
		if (unlikely(!pskb_may_pull(skb, 1))) {
			net_info_ratelimited("%s: NULL packet received from peer %u\n",
					     peer->ovpn->dev->name, peer->id);
			goto drop;
		}

		net_info_ratelimited("%s: unsupported protocol received from peer %u\n",
				     peer->ovpn->dev->name, peer->id);
		goto drop;
	}
	skb->protocol = proto;

	/* perform Reverse Path Filtering (RPF) */
	if (unlikely(!ovpn_peer_check_by_src(peer->ovpn, skb, peer))) {
		if (skb_protocol_to_family(skb) == AF_INET6)
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI6c\n",
					    peer->ovpn->dev->name, peer->id,
					    &ipv6_hdr(skb)->saddr);
		else
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI4\n",
					    peer->ovpn->dev->name, peer->id,
					    &ip_hdr(skb)->saddr);
		goto drop;
	}

	/* increment RX stats */
	ovpn_peer_stats_increment_rx(&peer->vpn_stats, skb->len);
	ovpn_peer_stats_increment_rx(&peer->link_stats,
				     ovpn_skb_cb(skb)->orig_len);

	ovpn_netdev_write(peer, skb);
	/* skb is passed to upper layer - don't free it */
	skb = NULL;
drop:
	if (unlikely(skb))
		dev_core_stats_rx_dropped_inc(peer->ovpn->dev);
	kfree_skb(skb);
	ovpn_peer_put(peer);
}

/* pick next packet from RX queue, decrypt and forward it to the device */
void ovpn_recv(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	u8 key_id;

	/* get the key slot matching the key ID in the received packet */
	key_id = ovpn_key_id_from_skb(skb);
	ks = ovpn_crypto_key_id_to_slot(&peer->crypto, key_id);
	if (unlikely(!ks)) {
		net_info_ratelimited("%s: no available key for peer %u, key-id: %u\n",
				     peer->ovpn->dev->name, peer->id, key_id);
		dev_core_stats_rx_dropped_inc(peer->ovpn->dev);
		kfree_skb(skb);
		return;
	}

	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->orig_len = skb->len;
	ovpn_decrypt_post(skb, ovpn_aead_decrypt(ks, skb));
}

void ovpn_encrypt_post(struct sk_buff *skb, int ret)
{
	struct ovpn_crypto_key_slot *ks = ovpn_skb_cb(skb)->ks;
	struct ovpn_peer *peer = ovpn_skb_cb(skb)->peer;

	/* encryption is happening asynchronously. This function will be
	 * called later by the crypto callback with a proper return value
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	if (unlikely(ret == -ERANGE)) {
		/* we ran out of IVs and we must kill the key as it can't be
		 * usea nymore
		 */
		netdev_warn(peer->ovpn->dev,
			    "killing primary key for peer %u\n", peer->id);
		ovpn_crypto_kill_primary(&peer->crypto);
		goto err;
	}

	if (unlikely(ret < 0))
		goto err;

	skb_mark_not_on_list(skb);
	ovpn_peer_stats_increment_tx(&peer->link_stats, skb->len);
	ovpn_peer_stats_increment_tx(&peer->vpn_stats,
				     ovpn_skb_cb(skb)->orig_len);

	switch (peer->sock->sock->sk->sk_protocol) {
	case IPPROTO_UDP:
		ovpn_udp_send_skb(peer->ovpn, peer, skb);
		break;
	default:
		/* no transport configured yet */
		goto err;
	}
	/* skb passed down the stack - don't free it */
	skb = NULL;
err:
	if (unlikely(skb)) {
		dev_core_stats_tx_dropped_inc(peer->ovpn->dev);
		kfree_skb(skb);
	}
	ovpn_crypto_key_slot_put(ks);
	ovpn_peer_put(peer);
}

static bool ovpn_encrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;

	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL &&
		     skb_checksum_help(skb))) {
		net_warn_ratelimited("%s: cannot compute checksum for outgoing packet\n",
				     peer->ovpn->dev->name);
		return false;
	}

	/* get primary key to be used for encrypting data */
	ks = ovpn_crypto_key_slot_primary(&peer->crypto);
	if (unlikely(!ks)) {
		net_warn_ratelimited("%s: error while retrieving primary key slot for peer %u\n",
				     peer->ovpn->dev->name, peer->id);
		return false;
	}

	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->orig_len = skb->len;

	/* take a reference to the peer because the crypto code may run async.
	 * ovpn_encrypt_post() will release it upon completion
	 */
	DEBUG_NET_WARN_ON_ONCE(!ovpn_peer_hold(peer));
	ovpn_encrypt_post(skb, ovpn_aead_encrypt(ks, skb, peer->id));
	return true;
}

/* send skb to connected peer, if any */
static void ovpn_send(struct ovpn_struct *ovpn, struct sk_buff *skb,
		      struct ovpn_peer *peer)
{
	struct sk_buff *curr, *next;

	if (likely(!peer))
		/* retrieve peer serving the destination IP of this packet */
		peer = ovpn_peer_get_by_dst(ovpn, skb);
	if (unlikely(!peer)) {
		net_dbg_ratelimited("%s: no peer to send data to\n",
				    ovpn->dev->name);
		dev_core_stats_tx_dropped_inc(ovpn->dev);
		goto drop;
	}

	/* this might be a GSO-segmented skb list: process each skb
	 * independently
	 */
	skb_list_walk_safe(skb, curr, next)
		if (unlikely(!ovpn_encrypt_one(peer, curr))) {
			dev_core_stats_tx_dropped_inc(ovpn->dev);
			kfree_skb(curr);
		}

	/* skb passed over, no need to free */
	skb = NULL;
drop:
	if (likely(peer))
		ovpn_peer_put(peer);
	kfree_skb_list(skb);
}

/* Send user data to the network
 */
netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovpn_struct *ovpn = netdev_priv(dev);
	struct sk_buff *segments, *tmp, *curr, *next;
	struct sk_buff_head skb_list;
	__be16 proto;
	int ret;

	/* reset netfilter state */
	nf_reset_ct(skb);

	/* verify IP header size in network packet */
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto || skb->protocol != proto)) {
		net_err_ratelimited("%s: dropping malformed payload packet\n",
				    dev->name);
		dev_core_stats_tx_dropped_inc(ovpn->dev);
		goto drop;
	}

	if (skb_is_gso(skb)) {
		segments = skb_gso_segment(skb, 0);
		if (IS_ERR(segments)) {
			ret = PTR_ERR(segments);
			net_err_ratelimited("%s: cannot segment packet: %d\n",
					    dev->name, ret);
			dev_core_stats_tx_dropped_inc(ovpn->dev);
			goto drop;
		}

		consume_skb(skb);
		skb = segments;
	}

	/* from this moment on, "skb" might be a list */

	__skb_queue_head_init(&skb_list);
	skb_list_walk_safe(skb, curr, next) {
		skb_mark_not_on_list(curr);

		tmp = skb_share_check(curr, GFP_ATOMIC);
		if (unlikely(!tmp)) {
			kfree_skb_list(next);
			net_err_ratelimited("%s: skb_share_check failed\n",
					    dev->name);
			goto drop_list;
		}

		__skb_queue_tail(&skb_list, tmp);
	}
	skb_list.prev->next = NULL;

	ovpn_send(ovpn, skb_list.next, NULL);

	return NETDEV_TX_OK;

drop_list:
	skb_queue_walk_safe(&skb_list, curr, next) {
		dev_core_stats_tx_dropped_inc(ovpn->dev);
		kfree_skb(curr);
	}
drop:
	skb_tx_error(skb);
	kfree_skb_list(skb);
	return NET_XMIT_DROP;
}
