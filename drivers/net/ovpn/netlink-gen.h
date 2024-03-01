/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/ovpn.yaml */
/* YNL-GEN kernel header */

#ifndef _LINUX_OVPN_GEN_H
#define _LINUX_OVPN_GEN_H

#include <net/netlink.h>
#include <net/genetlink.h>

#include <uapi/linux/ovpn.h>

/* Common nested types */
extern const struct nla_policy ovpn_keyconf_nl_policy[OVPN_A_KEYCONF_DECRYPT_DIR + 1];
extern const struct nla_policy ovpn_keydir_nl_policy[OVPN_A_KEYDIR_NONCE_TAIL + 1];
extern const struct nla_policy ovpn_peer_nl_policy[OVPN_A_PEER_LINK_TX_PACKETS + 1];

int ovpn_nl_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		     struct genl_info *info);
void
ovpn_nl_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		  struct genl_info *info);

int ovpn_nl_new_iface_doit(struct sk_buff *skb, struct genl_info *info);
int ovpn_nl_del_iface_doit(struct sk_buff *skb, struct genl_info *info);
int ovpn_nl_set_peer_doit(struct sk_buff *skb, struct genl_info *info);
int ovpn_nl_get_peer_doit(struct sk_buff *skb, struct genl_info *info);
int ovpn_nl_get_peer_dumpit(struct sk_buff *skb, struct netlink_callback *cb);
int ovpn_nl_del_peer_doit(struct sk_buff *skb, struct genl_info *info);
int ovpn_nl_set_key_doit(struct sk_buff *skb, struct genl_info *info);
int ovpn_nl_swap_keys_doit(struct sk_buff *skb, struct genl_info *info);
int ovpn_nl_del_key_doit(struct sk_buff *skb, struct genl_info *info);

enum {
	OVPN_NLGRP_PEERS,
};

extern struct genl_family ovpn_nl_family;

#endif /* _LINUX_OVPN_GEN_H */
