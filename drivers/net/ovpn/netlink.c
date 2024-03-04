// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2024 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
#include <net/genetlink.h>

#include <uapi/linux/ovpn.h>

#include "ovpnstruct.h"
#include "main.h"
#include "io.h"
#include "netlink.h"
#include "netlink-gen.h"
#include "bind.h"
#include "packet.h"
#include "peer.h"
#include "socket.h"

MODULE_ALIAS_GENL_FAMILY(OVPN_FAMILY_NAME);

/**
 * ovpn_get_dev_from_attrs - retrieve the netdevice a netlink message is
 *                           targeting
 * @net: network namespace where to look for the interface
 * @info: generic netlink info from the user request
 *
 * Return: the netdevice, if found, or an error otherwise
 */
static struct net_device *
ovpn_get_dev_from_attrs(struct net *net, const struct genl_info *info)
{
	struct net_device *dev;
	int ifindex;

	if (GENL_REQ_ATTR_CHECK(info, OVPN_A_IFINDEX))
		return ERR_PTR(-EINVAL);

	ifindex = nla_get_u32(info->attrs[OVPN_A_IFINDEX]);

	dev = dev_get_by_index(net, ifindex);
	if (!dev) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "ifindex does not match any interface");
		return ERR_PTR(-ENODEV);
	}

	if (!ovpn_dev_is_valid(dev))
		goto err_put_dev;

	return dev;

err_put_dev:
	netdev_put(dev, NULL);

	NL_SET_ERR_MSG_MOD(info->extack, "specified interface is not ovpn");
	NL_SET_BAD_ATTR(info->extack, info->attrs[OVPN_A_IFINDEX]);

	return ERR_PTR(-EINVAL);
}

int ovpn_nl_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		     struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct net_device *dev = ovpn_get_dev_from_attrs(net, info);

	if (IS_ERR(dev))
		return PTR_ERR(dev);

	info->user_ptr[0] = netdev_priv(dev);

	return 0;
}

void ovpn_nl_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		       struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];

	if (ovpn)
		netdev_put(ovpn->dev, NULL);
}

int ovpn_nl_new_iface_doit(struct sk_buff *skb, struct genl_info *info)
{
	const char *ifname = OVPN_DEFAULT_IFNAME;
	enum ovpn_mode mode = OVPN_MODE_P2P;
	struct net_device *dev;
	struct sk_buff *msg;
	void *hdr;

	if (info->attrs[OVPN_A_IFNAME])
		ifname = nla_data(info->attrs[OVPN_A_IFNAME]);

	if (info->attrs[OVPN_A_MODE]) {
		mode = nla_get_u32(info->attrs[OVPN_A_MODE]);
		pr_debug("ovpn: setting device (%s) mode: %u\n", ifname, mode);
	}

	dev = ovpn_iface_create(ifname, mode, genl_info_net(info));
	if (IS_ERR(dev)) {
		NL_SET_ERR_MSG_FMT_MOD(info->extack,
				       "error while creating interface: %ld",
				       PTR_ERR(dev));
		return PTR_ERR(dev);
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_iput(msg, info);
	if (!hdr) {
		nlmsg_free(msg);
		return -ENOBUFS;
	}

	if (nla_put_string(msg, OVPN_A_IFNAME, dev->name)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);

	return genlmsg_reply(msg, info);
}

int ovpn_nl_del_iface_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];

	rtnl_lock();
	ovpn_iface_destruct(ovpn);
	unregister_netdevice(ovpn->dev);
	netdev_put(ovpn->dev, NULL);
	rtnl_unlock();

	return 0;
}

static u8 *ovpn_nl_attr_local_ip(struct genl_info *info,
				 struct ovpn_struct *ovpn,
				 struct nlattr **attrs, int sock_fam)
{
	size_t ip_len = nla_len(attrs[OVPN_A_PEER_LOCAL_IP]);
	u8 *local_ip = nla_data(attrs[OVPN_A_PEER_LOCAL_IP]);
	bool is_mapped;

	if (ip_len == sizeof(struct in_addr)) {
		if (sock_fam != AF_INET) {
			NL_SET_ERR_MSG_MOD(info->extack,
					   "mismatching AF between local IP (v4) and peer");
			return ERR_PTR(-EINVAL);
		}
	} else if (ip_len == sizeof(struct in6_addr)) {
		is_mapped = ipv6_addr_v4mapped((struct in6_addr *)local_ip);

		if (sock_fam != AF_INET6 && !is_mapped) {
			NL_SET_ERR_MSG_MOD(info->extack,
					   "mismatching AF between local IP (v6) and peer");
			return ERR_PTR(-EINVAL);
		}

		if (is_mapped)
			/* this is an IPv6-mapped IPv4
			 * address, therefore extract
			 * the actual v4 address from
			 * the last 4 bytes
			 */
			local_ip += 12;
	} else {
		NL_SET_ERR_MSG_FMT_MOD(info->extack,
				       "invalid local IP length: %zu", ip_len);
		return ERR_PTR(-EINVAL);
	}

	return local_ip;
}

int ovpn_nl_set_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	bool keepalive_set = false, new_peer = false;
	struct nlattr *attrs[OVPN_A_PEER_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct sockaddr_storage *ss = NULL;
	u32 sockfd, id, interv, timeout;
	struct socket *sock = NULL;
	struct sockaddr_in mapped;
	struct sockaddr_in6 *in6;
	struct ovpn_peer *peer;
	u8 *local_ip = NULL;
	size_t sa_len;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, OVPN_A_PEER))
		return -EINVAL;

	ret = nla_parse_nested(attrs, OVPN_A_PEER_MAX, info->attrs[OVPN_A_PEER],
			       ovpn_peer_nl_policy, info->extack);
	if (ret)
		return ret;

	if (NL_REQ_ATTR_CHECK(info->extack, info->attrs[OVPN_A_PEER], attrs,
			      OVPN_A_PEER_ID))
		return -EINVAL;

	id = nla_get_u32(attrs[OVPN_A_PEER_ID]);
	/* check if the peer exists first, otherwise create a new one */
	peer = ovpn_peer_get_by_id(ovpn, id);
	if (!peer) {
		peer = ovpn_peer_new(ovpn, id);
		new_peer = true;
		if (IS_ERR(peer)) {
			NL_SET_ERR_MSG_FMT_MOD(info->extack,
					       "cannot create new peer object for peer %u (sockaddr=%pIScp): %ld",
					       id, ss, PTR_ERR(peer));
			return PTR_ERR(peer);
		}
	}

	if (new_peer && NL_REQ_ATTR_CHECK(info->extack,
					  info->attrs[OVPN_A_PEER], attrs,
					  OVPN_A_PEER_SOCKET)) {
		ret = -EINVAL;
		goto peer_release;
	}

	if (new_peer && ovpn->mode == OVPN_MODE_MP &&
	    !attrs[OVPN_A_PEER_VPN_IPV4] && !attrs[OVPN_A_PEER_VPN_IPV6]) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "a VPN IP is required when adding a peer in MP mode");
		ret = -EINVAL;
		goto peer_release;
	}

	if (attrs[OVPN_A_PEER_SOCKET]) {
		/* lookup the fd in the kernel table and extract the socket
		 * object
		 */
		sockfd = nla_get_u32(attrs[OVPN_A_PEER_SOCKET]);
		/* sockfd_lookup() increases sock's refcounter */
		sock = sockfd_lookup(sockfd, &ret);
		if (!sock) {
			NL_SET_ERR_MSG_FMT_MOD(info->extack,
					       "cannot lookup peer socket (fd=%u): %d",
					       sockfd, ret);
			ret = -ENOTSOCK;
			goto peer_release;
		}

		if (peer->sock)
			ovpn_socket_put(peer->sock);

		peer->sock = ovpn_socket_new(sock, peer);
		if (IS_ERR(peer->sock)) {
			NL_SET_ERR_MSG_FMT_MOD(info->extack,
					       "cannot encapsulate socket: %ld",
					       PTR_ERR(peer->sock));
			sockfd_put(sock);
			peer->sock = NULL;
			ret = -ENOTSOCK;
			goto peer_release;
		}
	}

	/* Only when using UDP as transport protocol the remote endpoint
	 * can be configured so that ovpn knows where to send packets
	 * to.
	 *
	 * In case of TCP, the socket is connected to the peer and ovpn
	 * will just send bytes over it, without the need to specify a
	 * destination.
	 */
	if (peer->sock->sock->sk->sk_protocol == IPPROTO_UDP &&
	    attrs[OVPN_A_PEER_SOCKADDR_REMOTE]) {
		ss = nla_data(attrs[OVPN_A_PEER_SOCKADDR_REMOTE]);
		sa_len = nla_len(attrs[OVPN_A_PEER_SOCKADDR_REMOTE]);
		switch (sa_len) {
		case sizeof(struct sockaddr_in):
			if (ss->ss_family == AF_INET)
				/* valid sockaddr */
				break;

			NL_SET_ERR_MSG_MOD(info->extack,
					   "remote sockaddr_in has invalid family");
			ret = -EINVAL;
			goto peer_release;
		case sizeof(struct sockaddr_in6):
			if (ss->ss_family == AF_INET6)
				/* valid sockaddr */
				break;

			NL_SET_ERR_MSG_MOD(info->extack,
					   "remote sockaddr_in6 has invalid family");
			ret = -EINVAL;
			goto peer_release;
		default:
			NL_SET_ERR_MSG_FMT_MOD(info->extack,
					       "invalid size for sockaddr: %zd",
					       sa_len);
			ret = -EINVAL;
			goto peer_release;
		}

		/* if this is a v6-mapped-v4, convert the sockaddr
		 * object from AF_INET6 to AF_INET before continue
		 * processing
		 */
		if (ss->ss_family == AF_INET6) {
			in6 = (struct sockaddr_in6 *)ss;

			if (ipv6_addr_v4mapped(&in6->sin6_addr)) {
				mapped.sin_family = AF_INET;
				mapped.sin_addr.s_addr =
					in6->sin6_addr.s6_addr32[3];
				mapped.sin_port = in6->sin6_port;
				ss = (struct sockaddr_storage *)&mapped;
			}
		}

		if (attrs[OVPN_A_PEER_LOCAL_IP]) {
			local_ip = ovpn_nl_attr_local_ip(info, ovpn,
							 attrs,
							 ss->ss_family);
			if (IS_ERR(local_ip)) {
				ret = PTR_ERR(local_ip);
				NL_SET_ERR_MSG_FMT_MOD(info->extack,
						       "cannot retrieve local IP: %d",
						       ret);
				goto peer_release;
			}
		}

		/* set peer sockaddr */
		ret = ovpn_peer_reset_sockaddr(peer, ss, local_ip);
		if (ret < 0) {
			NL_SET_ERR_MSG_FMT_MOD(info->extack,
					       "cannot set peer sockaddr: %d",
					       ret);
			goto peer_release;
		}
	}

	/* VPN IPs cannot be updated, because they are hashed */
	if (new_peer && attrs[OVPN_A_PEER_VPN_IPV4])
		peer->vpn_addrs.ipv4.s_addr =
			nla_get_in_addr(attrs[OVPN_A_PEER_VPN_IPV4]);

	/* VPN IPs cannot be updated, because they are hashed */
	if (new_peer && attrs[OVPN_A_PEER_VPN_IPV6])
		peer->vpn_addrs.ipv6 =
			nla_get_in6_addr(attrs[OVPN_A_PEER_VPN_IPV6]);

	/* when setting the keepalive, both parameters have to be configured */
	if (attrs[OVPN_A_PEER_KEEPALIVE_INTERVAL] &&
	    attrs[OVPN_A_PEER_KEEPALIVE_TIMEOUT]) {
		keepalive_set = true;
		interv = nla_get_u32(attrs[OVPN_A_PEER_KEEPALIVE_INTERVAL]);
		timeout = nla_get_u32(attrs[OVPN_A_PEER_KEEPALIVE_TIMEOUT]);
	}

	if (keepalive_set)
		ovpn_peer_keepalive_set(peer, interv, timeout);

	netdev_dbg(ovpn->dev,
		   "%s: %s peer with endpoint=%pIScp/%s id=%u VPN-IPv4=%pI4 VPN-IPv6=%pI6c\n",
		   __func__, (new_peer ? "adding" : "modifying"), ss,
		   peer->sock->sock->sk->sk_prot_creator->name, peer->id,
		   &peer->vpn_addrs.ipv4.s_addr, &peer->vpn_addrs.ipv6);

	if (new_peer) {
		ret = ovpn_peer_add(ovpn, peer);
		if (ret < 0) {
			NL_SET_ERR_MSG_FMT_MOD(info->extack,
					       "cannot add new peer (id=%u) to hashtable: %d\n",
					       peer->id, ret);
			goto peer_release;
		}
	} else {
		ovpn_peer_put(peer);
	}

	return 0;

peer_release:
	if (new_peer) {
		/* release right away because peer is not really used in any
		 * context
		 */
		ovpn_peer_release(peer);
		kfree(peer);
	} else {
		ovpn_peer_put(peer);
	}

	return ret;
}

static int ovpn_nl_send_peer(struct sk_buff *skb, const struct genl_info *info,
			     const struct ovpn_peer *peer, u32 portid, u32 seq,
			     int flags)
{
	const struct ovpn_bind *bind;
	struct nlattr *attr;
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &ovpn_nl_family, flags,
			  OVPN_CMD_SET_PEER);
	if (!hdr)
		return -ENOBUFS;

	attr = nla_nest_start(skb, OVPN_A_PEER);
	if (!attr)
		goto err;

	if (nla_put_u32(skb, OVPN_A_PEER_ID, peer->id))
		goto err;

	if (peer->vpn_addrs.ipv4.s_addr != htonl(INADDR_ANY))
		if (nla_put_in_addr(skb, OVPN_A_PEER_VPN_IPV4,
				    peer->vpn_addrs.ipv4.s_addr))
			goto err;

	if (!ipv6_addr_equal(&peer->vpn_addrs.ipv6, &in6addr_any))
		if (nla_put_in6_addr(skb, OVPN_A_PEER_VPN_IPV6,
				     &peer->vpn_addrs.ipv6))
			goto err;

	if (nla_put_u32(skb, OVPN_A_PEER_KEEPALIVE_INTERVAL,
			peer->keepalive_interval) ||
	    nla_put_u32(skb, OVPN_A_PEER_KEEPALIVE_TIMEOUT,
			peer->keepalive_timeout))
		goto err;

	rcu_read_lock();
	bind = rcu_dereference(peer->bind);
	if (bind) {
		if (bind->sa.in4.sin_family == AF_INET) {
			if (nla_put(skb, OVPN_A_PEER_SOCKADDR_REMOTE,
				    sizeof(bind->sa.in4), &bind->sa.in4) ||
			    nla_put(skb, OVPN_A_PEER_LOCAL_IP,
				    sizeof(bind->local.ipv4),
				    &bind->local.ipv4))
				goto err_unlock;
		} else if (bind->sa.in4.sin_family == AF_INET6) {
			if (nla_put(skb, OVPN_A_PEER_SOCKADDR_REMOTE,
				    sizeof(bind->sa.in6), &bind->sa.in6) ||
			    nla_put(skb, OVPN_A_PEER_LOCAL_IP,
				    sizeof(bind->local.ipv6),
				    &bind->local.ipv6))
				goto err_unlock;
		}
	}
	rcu_read_unlock();

	if (nla_put_net16(skb, OVPN_A_PEER_LOCAL_PORT,
			  inet_sk(peer->sock->sock->sk)->inet_sport) ||
	    /* VPN RX stats */
	    nla_put_uint(skb, OVPN_A_PEER_VPN_RX_BYTES,
			 atomic64_read(&peer->vpn_stats.rx.bytes)) ||
	    nla_put_uint(skb, OVPN_A_PEER_VPN_RX_PACKETS,
			 atomic64_read(&peer->vpn_stats.rx.packets)) ||
	    /* VPN TX stats */
	    nla_put_uint(skb, OVPN_A_PEER_VPN_TX_BYTES,
			 atomic64_read(&peer->vpn_stats.tx.bytes)) ||
	    nla_put_uint(skb, OVPN_A_PEER_VPN_TX_PACKETS,
			 atomic64_read(&peer->vpn_stats.tx.packets)) ||
	    /* link RX stats */
	    nla_put_uint(skb, OVPN_A_PEER_LINK_RX_BYTES,
			 atomic64_read(&peer->link_stats.rx.bytes)) ||
	    nla_put_uint(skb, OVPN_A_PEER_LINK_RX_PACKETS,
			 atomic64_read(&peer->link_stats.rx.packets)) ||
	    /* link TX stats */
	    nla_put_uint(skb, OVPN_A_PEER_LINK_TX_BYTES,
			 atomic64_read(&peer->link_stats.tx.bytes)) ||
	    nla_put_uint(skb, OVPN_A_PEER_LINK_TX_PACKETS,
			 atomic64_read(&peer->link_stats.tx.packets)))
		goto err;

	nla_nest_end(skb, attr);
	genlmsg_end(skb, hdr);

	return 0;
err_unlock:
	rcu_read_unlock();
err:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

int ovpn_nl_get_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *attrs[OVPN_A_PEER_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_peer *peer;
	struct sk_buff *msg;
	u32 peer_id;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, OVPN_A_PEER))
		return -EINVAL;

	ret = nla_parse_nested(attrs, OVPN_A_PEER_MAX, info->attrs[OVPN_A_PEER],
			       ovpn_peer_nl_policy, info->extack);
	if (ret)
		return ret;

	if (NL_REQ_ATTR_CHECK(info->extack, info->attrs[OVPN_A_PEER], attrs,
			      OVPN_A_PEER_ID))
		return -EINVAL;

	peer_id = nla_get_u32(attrs[OVPN_A_PEER_ID]);
	peer = ovpn_peer_get_by_id(ovpn, peer_id);
	if (!peer) {
		NL_SET_ERR_MSG_FMT_MOD(info->extack,
				       "cannot find peer with id %u", peer_id);
		return -ENOENT;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	ret = ovpn_nl_send_peer(msg, info, peer, info->snd_portid,
				info->snd_seq, 0);
	if (ret < 0) {
		nlmsg_free(msg);
		goto err;
	}

	ret = genlmsg_reply(msg, info);
err:
	ovpn_peer_put(peer);
	return ret;
}

int ovpn_nl_get_peer_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct genl_info *info = genl_info_dump(cb);
	struct ovpn_struct *ovpn;
	struct ovpn_peer *peer;
	struct net_device *dev;
	int bkt, last_idx = cb->args[1], dumped = 0;

	dev = ovpn_get_dev_from_attrs(sock_net(cb->skb->sk), info);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	ovpn = netdev_priv(dev);

	if (ovpn->mode == OVPN_MODE_P2P) {
		/* if we already dumped a peer it means we are done */
		if (last_idx)
			goto out;

		rcu_read_lock();
		peer = rcu_dereference(ovpn->peer);
		if (peer) {
			if (ovpn_nl_send_peer(skb, info, peer,
					      NETLINK_CB(cb->skb).portid,
					      cb->nlh->nlmsg_seq,
					      NLM_F_MULTI) == 0)
				dumped++;
		}
		rcu_read_unlock();
	} else {
		rcu_read_lock();
		hash_for_each_rcu(ovpn->peers->by_id, bkt, peer,
				  hash_entry_id) {
			/* skip already dumped peers that were dumped by
			 * previous invocations
			 */
			if (last_idx > 0) {
				last_idx--;
				continue;
			}

			if (ovpn_nl_send_peer(skb, info, peer,
					      NETLINK_CB(cb->skb).portid,
					      cb->nlh->nlmsg_seq,
					      NLM_F_MULTI) < 0)
				break;

			/* count peers being dumped during this invocation */
			dumped++;
		}
		rcu_read_unlock();
	}

out:
	netdev_put(dev, NULL);

	/* sum up peers dumped in this message, so that at the next invocation
	 * we can continue from where we left
	 */
	cb->args[1] += dumped;
	return skb->len;
}

int ovpn_nl_del_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *attrs[OVPN_A_PEER_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_peer *peer;
	u32 peer_id;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, OVPN_A_PEER))
		return -EINVAL;

	ret = nla_parse_nested(attrs, OVPN_A_PEER_MAX, info->attrs[OVPN_A_PEER],
			       ovpn_peer_nl_policy, info->extack);
	if (ret)
		return ret;

	if (NL_REQ_ATTR_CHECK(info->extack, info->attrs[OVPN_A_PEER], attrs,
			      OVPN_A_PEER_ID))
		return -EINVAL;

	peer_id = nla_get_u32(attrs[OVPN_A_PEER_ID]);

	peer = ovpn_peer_get_by_id(ovpn, peer_id);
	if (!peer)
		return -ENOENT;

	netdev_dbg(ovpn->dev, "%s: peer id=%u\n", __func__, peer->id);
	ret = ovpn_peer_del(peer, OVPN_DEL_PEER_REASON_USERSPACE);
	ovpn_peer_put(peer);

	return ret;
}

static int ovpn_nl_get_key_dir(struct genl_info *info, struct nlattr *key,
			       enum ovpn_cipher_alg cipher,
			       struct ovpn_key_direction *dir)
{
	struct nlattr *attrs[OVPN_A_KEYDIR_MAX + 1];
	int ret;

	ret = nla_parse_nested(attrs, OVPN_A_KEYDIR_MAX, key,
			       ovpn_keydir_nl_policy, info->extack);
	if (ret)
		return ret;

	switch (cipher) {
	case OVPN_CIPHER_ALG_AES_GCM:
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
		if (NL_REQ_ATTR_CHECK(info->extack, key, attrs,
				      OVPN_A_KEYDIR_CIPHER_KEY) ||
		    NL_REQ_ATTR_CHECK(info->extack, key, attrs,
				      OVPN_A_KEYDIR_NONCE_TAIL))
			return -EINVAL;

		dir->cipher_key = nla_data(attrs[OVPN_A_KEYDIR_CIPHER_KEY]);
		dir->cipher_key_size = nla_len(attrs[OVPN_A_KEYDIR_CIPHER_KEY]);

		/* These algorithms require a 96bit nonce,
		 * Construct it by combining 4-bytes packet id and
		 * 8-bytes nonce-tail from userspace
		 */
		dir->nonce_tail = nla_data(attrs[OVPN_A_KEYDIR_NONCE_TAIL]);
		dir->nonce_tail_size = nla_len(attrs[OVPN_A_KEYDIR_NONCE_TAIL]);
		break;
	default:
		NL_SET_ERR_MSG_MOD(info->extack, "unsupported cipher");
		return -EINVAL;
	}

	return 0;
}

int ovpn_nl_set_key_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *p_attrs[OVPN_A_PEER_MAX + 1];
	struct nlattr *attrs[OVPN_A_KEYCONF_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct ovpn_peer_key_reset pkr;
	struct ovpn_peer *peer;
	u32 peer_id;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, OVPN_A_PEER))
		return -EINVAL;

	ret = nla_parse_nested(p_attrs, OVPN_A_PEER_MAX,
			       info->attrs[OVPN_A_PEER], ovpn_peer_nl_policy,
			       info->extack);
	if (ret)
		return ret;

	if (NL_REQ_ATTR_CHECK(info->extack, info->attrs[OVPN_A_PEER], p_attrs,
			      OVPN_A_PEER_ID) ||
	    NL_REQ_ATTR_CHECK(info->extack, info->attrs[OVPN_A_PEER], p_attrs,
			      OVPN_A_PEER_KEYCONF))
		return -EINVAL;

	ret = nla_parse_nested(attrs, OVPN_A_KEYCONF_MAX,
			       p_attrs[OVPN_A_PEER_KEYCONF],
			       ovpn_keyconf_nl_policy, info->extack);
	if (ret)
		return ret;

	if (NL_REQ_ATTR_CHECK(info->extack, p_attrs[OVPN_A_PEER_KEYCONF], attrs,
			      OVPN_A_KEYCONF_SLOT) ||
	    NL_REQ_ATTR_CHECK(info->extack, p_attrs[OVPN_A_PEER_KEYCONF], attrs,
			      OVPN_A_KEYCONF_KEY_ID) ||
	    NL_REQ_ATTR_CHECK(info->extack, p_attrs[OVPN_A_PEER_KEYCONF], attrs,
			      OVPN_A_KEYCONF_CIPHER_ALG) ||
	    NL_REQ_ATTR_CHECK(info->extack, p_attrs[OVPN_A_PEER_KEYCONF], attrs,
			      OVPN_A_KEYCONF_ENCRYPT_DIR) ||
	    NL_REQ_ATTR_CHECK(info->extack, p_attrs[OVPN_A_PEER_KEYCONF], attrs,
			      OVPN_A_KEYCONF_DECRYPT_DIR))
		return -EINVAL;

	peer_id = nla_get_u32(p_attrs[OVPN_A_PEER_ID]);
	pkr.slot = nla_get_u8(attrs[OVPN_A_KEYCONF_SLOT]);
	pkr.key.key_id = nla_get_u16(attrs[OVPN_A_KEYCONF_KEY_ID]);
	pkr.key.cipher_alg = nla_get_u16(attrs[OVPN_A_KEYCONF_CIPHER_ALG]);

	ret = ovpn_nl_get_key_dir(info, attrs[OVPN_A_KEYCONF_ENCRYPT_DIR],
				  pkr.key.cipher_alg, &pkr.key.encrypt);
	if (ret < 0)
		return ret;

	ret = ovpn_nl_get_key_dir(info, attrs[OVPN_A_KEYCONF_DECRYPT_DIR],
				  pkr.key.cipher_alg, &pkr.key.decrypt);
	if (ret < 0)
		return ret;

	peer = ovpn_peer_get_by_id(ovpn, peer_id);
	if (!peer) {
		NL_SET_ERR_MSG_FMT_MOD(info->extack,
				       "no peer with id %u to set key for",
				       peer_id);
		return -ENOENT;
	}

	ret = ovpn_crypto_state_reset(&peer->crypto, &pkr);
	if (ret < 0) {
		NL_SET_ERR_MSG_FMT_MOD(info->extack,
				       "cannot install new key for peer %u",
				       peer_id);
		goto out;
	}

	netdev_dbg(ovpn->dev, "%s: new key installed (id=%u) for peer %u\n",
		   __func__, pkr.key.key_id, peer_id);
out:
	ovpn_peer_put(peer);
	return ret;
}

int ovpn_nl_swap_keys_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct ovpn_struct *ovpn = info->user_ptr[0];
	struct nlattr *attrs[OVPN_A_PEER_MAX + 1];
	struct ovpn_peer *peer;
	u32 peer_id;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, OVPN_A_PEER))
		return -EINVAL;

	ret = nla_parse_nested(attrs, OVPN_A_PEER_MAX, info->attrs[OVPN_A_PEER],
			       ovpn_peer_nl_policy, info->extack);
	if (ret)
		return ret;

	if (NL_REQ_ATTR_CHECK(info->extack, info->attrs[OVPN_A_PEER], attrs,
			      OVPN_A_PEER_ID))
		return -EINVAL;

	peer_id = nla_get_u32(attrs[OVPN_A_PEER_ID]);

	peer = ovpn_peer_get_by_id(ovpn, peer_id);
	if (!peer) {
		NL_SET_ERR_MSG_FMT_MOD(info->extack,
				       "no peer with id %u to swap keys for",
				       peer_id);
		return -ENOENT;
	}

	ovpn_crypto_key_slots_swap(&peer->crypto);
	ovpn_peer_put(peer);

	return 0;
}

int ovpn_nl_del_key_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *p_attrs[OVPN_A_PEER_MAX + 1];
	struct nlattr *attrs[OVPN_A_KEYCONF_MAX + 1];
	struct ovpn_struct *ovpn = info->user_ptr[0];
	enum ovpn_key_slot slot;
	struct ovpn_peer *peer;
	u32 peer_id;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, OVPN_A_PEER))
		return -EINVAL;

	ret = nla_parse_nested(p_attrs, OVPN_A_PEER_MAX,
			       info->attrs[OVPN_A_PEER], ovpn_peer_nl_policy,
			       info->extack);
	if (ret)
		return ret;

	if (NL_REQ_ATTR_CHECK(info->extack, info->attrs[OVPN_A_PEER], p_attrs,
			      OVPN_A_PEER_ID) ||
	    NL_REQ_ATTR_CHECK(info->extack, info->attrs[OVPN_A_PEER], p_attrs,
			      OVPN_A_PEER_KEYCONF))
		return -EINVAL;

	ret = nla_parse_nested(attrs, OVPN_A_KEYCONF_MAX,
			       p_attrs[OVPN_A_PEER_KEYCONF],
			       ovpn_keyconf_nl_policy, info->extack);
	if (ret)
		return ret;

	if (NL_REQ_ATTR_CHECK(info->extack, p_attrs[OVPN_A_PEER_KEYCONF], attrs,
			      OVPN_A_KEYCONF_SLOT))
		return -EINVAL;

	peer_id = nla_get_u32(p_attrs[OVPN_A_PEER_ID]);
	slot = nla_get_u8(attrs[OVPN_A_KEYCONF_SLOT]);

	peer = ovpn_peer_get_by_id(ovpn, peer_id);
	if (!peer) {
		NL_SET_ERR_MSG_FMT_MOD(info->extack,
				       "no peer with id %u to delete key for",
				       peer_id);
		return -ENOENT;
	}

	ovpn_crypto_key_slot_delete(&peer->crypto, slot);
	ovpn_peer_put(peer);

	return 0;
}

int ovpn_nl_notify_del_peer(struct ovpn_peer *peer)
{
	struct sk_buff *msg;
	struct nlattr *attr;
	int ret = -EMSGSIZE;
	void *hdr;

	netdev_info(peer->ovpn->dev, "deleting peer with id %u, reason %d\n",
		    peer->id, peer->delete_reason);

	msg = nlmsg_new(100, GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &ovpn_nl_family, 0, OVPN_CMD_DEL_PEER);
	if (!hdr) {
		ret = -ENOBUFS;
		goto err_free_msg;
	}

	if (nla_put_u32(msg, OVPN_A_IFINDEX, peer->ovpn->dev->ifindex))
		goto err_cancel_msg;

	attr = nla_nest_start(msg, OVPN_A_PEER);
	if (!attr)
		goto err_cancel_msg;

	if (nla_put_u8(msg, OVPN_A_PEER_DEL_REASON, peer->delete_reason))
		goto err_cancel_msg;

	if (nla_put_u32(msg, OVPN_A_PEER_ID, peer->id))
		goto err_cancel_msg;

	nla_nest_end(msg, attr);

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&ovpn_nl_family, dev_net(peer->ovpn->dev), msg,
				0, OVPN_NLGRP_PEERS, GFP_ATOMIC);

	return 0;

err_cancel_msg:
	genlmsg_cancel(msg, hdr);
err_free_msg:
	nlmsg_free(msg);
	return ret;
}

int ovpn_nl_notify_swap_keys(struct ovpn_peer *peer)
{
	struct sk_buff *msg;
	int ret = -EMSGSIZE;
	void *hdr;

	netdev_info(peer->ovpn->dev, "peer with id %u must rekey - primary key unusable.\n",
		    peer->id);

	msg = nlmsg_new(100, GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &ovpn_nl_family, 0, OVPN_CMD_SWAP_KEYS);
	if (!hdr) {
		ret = -ENOBUFS;
		goto err_free_msg;
	}

	if (nla_put_u32(msg, OVPN_A_IFINDEX, peer->ovpn->dev->ifindex))
		goto err_cancel_msg;

	if (nla_put_u32(msg, OVPN_A_PEER_ID, peer->id))
		goto err_cancel_msg;

	genlmsg_end(msg, hdr);

	genlmsg_multicast_netns(&ovpn_nl_family, dev_net(peer->ovpn->dev), msg,
				0, OVPN_NLGRP_PEERS, GFP_ATOMIC);

	return 0;

err_cancel_msg:
	genlmsg_cancel(msg, hdr);
err_free_msg:
	nlmsg_free(msg);
	return ret;
}

/**
 * ovpn_nl_register - perform any needed registration in the NL subsustem
 *
 * Return: 0 on success, a negative error code otherwise
 */
int __init ovpn_nl_register(void)
{
	int ret = genl_register_family(&ovpn_nl_family);

	if (ret) {
		pr_err("ovpn: genl_register_family failed: %d\n", ret);
		return ret;
	}

	return 0;
}

/**
 * ovpn_nl_unregister - undo any module wide netlink registration
 */
void ovpn_nl_unregister(void)
{
	genl_unregister_family(&ovpn_nl_family);
}
