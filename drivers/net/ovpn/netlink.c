// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2024 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include <linux/netdevice.h>
#include <net/genetlink.h>

#include <uapi/linux/ovpn.h>

#include "ovpnstruct.h"
#include "main.h"
#include "io.h"
#include "netlink.h"
#include "netlink-gen.h"

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
ovpn_get_dev_from_attrs(struct net *net, struct genl_info *info)
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
	return -EOPNOTSUPP;
}

int ovpn_nl_del_iface_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int ovpn_nl_set_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int ovpn_nl_get_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int ovpn_nl_get_peer_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	return -EOPNOTSUPP;
}

int ovpn_nl_del_peer_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int ovpn_nl_set_key_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int ovpn_nl_swap_keys_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
}

int ovpn_nl_del_key_doit(struct sk_buff *skb, struct genl_info *info)
{
	return -EOPNOTSUPP;
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
