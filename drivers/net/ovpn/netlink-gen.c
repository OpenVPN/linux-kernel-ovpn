// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/ovpn.yaml */
/* YNL-GEN kernel source */

#include <net/netlink.h>
#include <net/genetlink.h>

#include "netlink-gen.h"

#include <uapi/linux/ovpn.h>

/* Integer value ranges */
static const struct netlink_range_validation ovpn_a_peer_id_range = {
	.max	= 16777215ULL,
};

static const struct netlink_range_validation ovpn_a_peer_local_port_range = {
	.min	= 1ULL,
	.max	= 65535ULL,
};

/* Common nested types */
const struct nla_policy ovpn_keyconf_nl_policy[OVPN_A_KEYCONF_DECRYPT_DIR + 1] = {
	[OVPN_A_KEYCONF_SLOT] = NLA_POLICY_MAX(NLA_U32, 1),
	[OVPN_A_KEYCONF_KEY_ID] = NLA_POLICY_MAX(NLA_U32, 7),
	[OVPN_A_KEYCONF_CIPHER_ALG] = NLA_POLICY_MAX(NLA_U32, 2),
	[OVPN_A_KEYCONF_ENCRYPT_DIR] = NLA_POLICY_NESTED(ovpn_keydir_nl_policy),
	[OVPN_A_KEYCONF_DECRYPT_DIR] = NLA_POLICY_NESTED(ovpn_keydir_nl_policy),
};

const struct nla_policy ovpn_keydir_nl_policy[OVPN_A_KEYDIR_NONCE_TAIL + 1] = {
	[OVPN_A_KEYDIR_CIPHER_KEY] = NLA_POLICY_MAX_LEN(256),
	[OVPN_A_KEYDIR_NONCE_TAIL] = NLA_POLICY_EXACT_LEN(OVPN_NONCE_TAIL_SIZE),
};

const struct nla_policy ovpn_peer_nl_policy[OVPN_A_PEER_LINK_TX_PACKETS + 1] = {
	[OVPN_A_PEER_ID] = NLA_POLICY_FULL_RANGE(NLA_U32, &ovpn_a_peer_id_range),
	[OVPN_A_PEER_SOCKADDR_REMOTE] = { .type = NLA_BINARY, },
	[OVPN_A_PEER_SOCKET] = { .type = NLA_U32, },
	[OVPN_A_PEER_VPN_IPV4] = { .type = NLA_U32, },
	[OVPN_A_PEER_VPN_IPV6] = NLA_POLICY_EXACT_LEN(16),
	[OVPN_A_PEER_LOCAL_IP] = NLA_POLICY_MAX_LEN(16),
	[OVPN_A_PEER_LOCAL_PORT] = NLA_POLICY_FULL_RANGE(NLA_U32, &ovpn_a_peer_local_port_range),
	[OVPN_A_PEER_KEEPALIVE_INTERVAL] = { .type = NLA_U32, },
	[OVPN_A_PEER_KEEPALIVE_TIMEOUT] = { .type = NLA_U32, },
	[OVPN_A_PEER_DEL_REASON] = NLA_POLICY_MAX(NLA_U32, 4),
	[OVPN_A_PEER_KEYCONF] = NLA_POLICY_NESTED(ovpn_keyconf_nl_policy),
	[OVPN_A_PEER_VPN_RX_BYTES] = { .type = NLA_UINT, },
	[OVPN_A_PEER_VPN_TX_BYTES] = { .type = NLA_UINT, },
	[OVPN_A_PEER_VPN_RX_PACKETS] = { .type = NLA_UINT, },
	[OVPN_A_PEER_VPN_TX_PACKETS] = { .type = NLA_UINT, },
	[OVPN_A_PEER_LINK_RX_BYTES] = { .type = NLA_UINT, },
	[OVPN_A_PEER_LINK_TX_BYTES] = { .type = NLA_UINT, },
	[OVPN_A_PEER_LINK_RX_PACKETS] = { .type = NLA_U32, },
	[OVPN_A_PEER_LINK_TX_PACKETS] = { .type = NLA_U32, },
};

/* OVPN_CMD_NEW_IFACE - do */
static const struct nla_policy ovpn_new_iface_nl_policy[OVPN_A_MODE + 1] = {
	[OVPN_A_IFNAME] = { .type = NLA_NUL_STRING, },
	[OVPN_A_MODE] = NLA_POLICY_MAX(NLA_U32, 1),
};

/* OVPN_CMD_DEL_IFACE - do */
static const struct nla_policy ovpn_del_iface_nl_policy[OVPN_A_IFINDEX + 1] = {
	[OVPN_A_IFINDEX] = { .type = NLA_U32, },
};

/* OVPN_CMD_SET_PEER - do */
static const struct nla_policy ovpn_set_peer_nl_policy[OVPN_A_PEER + 1] = {
	[OVPN_A_IFINDEX] = { .type = NLA_U32, },
	[OVPN_A_PEER] = NLA_POLICY_NESTED(ovpn_peer_nl_policy),
};

/* OVPN_CMD_GET_PEER - do */
static const struct nla_policy ovpn_get_peer_do_nl_policy[OVPN_A_PEER + 1] = {
	[OVPN_A_IFINDEX] = { .type = NLA_U32, },
	[OVPN_A_PEER] = NLA_POLICY_NESTED(ovpn_peer_nl_policy),
};

/* OVPN_CMD_GET_PEER - dump */
static const struct nla_policy ovpn_get_peer_dump_nl_policy[OVPN_A_IFINDEX + 1] = {
	[OVPN_A_IFINDEX] = { .type = NLA_U32, },
};

/* OVPN_CMD_DEL_PEER - do */
static const struct nla_policy ovpn_del_peer_nl_policy[OVPN_A_PEER + 1] = {
	[OVPN_A_IFINDEX] = { .type = NLA_U32, },
	[OVPN_A_PEER] = NLA_POLICY_NESTED(ovpn_peer_nl_policy),
};

/* OVPN_CMD_SET_KEY - do */
static const struct nla_policy ovpn_set_key_nl_policy[OVPN_A_PEER + 1] = {
	[OVPN_A_IFINDEX] = { .type = NLA_U32, },
	[OVPN_A_PEER] = NLA_POLICY_NESTED(ovpn_peer_nl_policy),
};

/* OVPN_CMD_SWAP_KEYS - do */
static const struct nla_policy ovpn_swap_keys_nl_policy[OVPN_A_PEER + 1] = {
	[OVPN_A_IFINDEX] = { .type = NLA_U32, },
	[OVPN_A_PEER] = NLA_POLICY_NESTED(ovpn_peer_nl_policy),
};

/* OVPN_CMD_DEL_KEY - do */
static const struct nla_policy ovpn_del_key_nl_policy[OVPN_A_PEER + 1] = {
	[OVPN_A_IFINDEX] = { .type = NLA_U32, },
	[OVPN_A_PEER] = NLA_POLICY_NESTED(ovpn_peer_nl_policy),
};

/* Ops table for ovpn */
static const struct genl_split_ops ovpn_nl_ops[] = {
	{
		.cmd		= OVPN_CMD_NEW_IFACE,
		.doit		= ovpn_nl_new_iface_doit,
		.policy		= ovpn_new_iface_nl_policy,
		.maxattr	= OVPN_A_MODE,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= OVPN_CMD_DEL_IFACE,
		.pre_doit	= ovpn_nl_pre_doit,
		.doit		= ovpn_nl_del_iface_doit,
		.post_doit	= ovpn_nl_post_doit,
		.policy		= ovpn_del_iface_nl_policy,
		.maxattr	= OVPN_A_IFINDEX,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= OVPN_CMD_SET_PEER,
		.pre_doit	= ovpn_nl_pre_doit,
		.doit		= ovpn_nl_set_peer_doit,
		.post_doit	= ovpn_nl_post_doit,
		.policy		= ovpn_set_peer_nl_policy,
		.maxattr	= OVPN_A_PEER,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= OVPN_CMD_GET_PEER,
		.pre_doit	= ovpn_nl_pre_doit,
		.doit		= ovpn_nl_get_peer_doit,
		.post_doit	= ovpn_nl_post_doit,
		.policy		= ovpn_get_peer_do_nl_policy,
		.maxattr	= OVPN_A_PEER,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= OVPN_CMD_GET_PEER,
		.dumpit		= ovpn_nl_get_peer_dumpit,
		.policy		= ovpn_get_peer_dump_nl_policy,
		.maxattr	= OVPN_A_IFINDEX,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DUMP,
	},
	{
		.cmd		= OVPN_CMD_DEL_PEER,
		.pre_doit	= ovpn_nl_pre_doit,
		.doit		= ovpn_nl_del_peer_doit,
		.post_doit	= ovpn_nl_post_doit,
		.policy		= ovpn_del_peer_nl_policy,
		.maxattr	= OVPN_A_PEER,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= OVPN_CMD_SET_KEY,
		.pre_doit	= ovpn_nl_pre_doit,
		.doit		= ovpn_nl_set_key_doit,
		.post_doit	= ovpn_nl_post_doit,
		.policy		= ovpn_set_key_nl_policy,
		.maxattr	= OVPN_A_PEER,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= OVPN_CMD_SWAP_KEYS,
		.pre_doit	= ovpn_nl_pre_doit,
		.doit		= ovpn_nl_swap_keys_doit,
		.post_doit	= ovpn_nl_post_doit,
		.policy		= ovpn_swap_keys_nl_policy,
		.maxattr	= OVPN_A_PEER,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd		= OVPN_CMD_DEL_KEY,
		.pre_doit	= ovpn_nl_pre_doit,
		.doit		= ovpn_nl_del_key_doit,
		.post_doit	= ovpn_nl_post_doit,
		.policy		= ovpn_del_key_nl_policy,
		.maxattr	= OVPN_A_PEER,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
};

static const struct genl_multicast_group ovpn_nl_mcgrps[] = {
	[OVPN_NLGRP_PEERS] = { "peers", },
};

struct genl_family ovpn_nl_family __ro_after_init = {
	.name		= OVPN_FAMILY_NAME,
	.version	= OVPN_FAMILY_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.split_ops	= ovpn_nl_ops,
	.n_split_ops	= ARRAY_SIZE(ovpn_nl_ops),
	.mcgrps		= ovpn_nl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(ovpn_nl_mcgrps),
};
