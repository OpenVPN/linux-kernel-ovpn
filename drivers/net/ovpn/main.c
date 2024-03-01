// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2024 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#include <linux/genetlink.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <net/rtnetlink.h>
#include <uapi/linux/ovpn.h>

#include "ovpnstruct.h"
#include "main.h"
#include "netlink.h"
#include "io.h"

/* Driver info */
#define DRV_DESCRIPTION	"OpenVPN data channel offload (ovpn)"
#define DRV_COPYRIGHT	"(C) 2020-2024 OpenVPN, Inc."

/**
 * ovpn_dev_is_valid - check if the netdevice is of type 'ovpn'
 * @dev: the interface to check
 *
 * Return: whether the netdevice is of type 'ovpn'
 */
bool ovpn_dev_is_valid(const struct net_device *dev)
{
	return dev->netdev_ops->ndo_start_xmit == ovpn_net_xmit;
}

/* we register with rtnl to let core know that ovpn is a virtual driver and
 * therefore ifaces should be destroyed when exiting a netns
 */
static struct rtnl_link_ops ovpn_link_ops = {
	.kind = OVPN_FAMILY_NAME,
};

static int ovpn_netdev_notifier_call(struct notifier_block *nb,
				     unsigned long state, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (!ovpn_dev_is_valid(dev))
		return NOTIFY_DONE;

	switch (state) {
	case NETDEV_REGISTER:
		/* add device to internal list for later destruction upon
		 * unregistration
		 */
		break;
	case NETDEV_UNREGISTER:
		/* can be delivered multiple times, so check registered flag,
		 * then destroy the interface
		 */
		break;
	case NETDEV_POST_INIT:
	case NETDEV_GOING_DOWN:
	case NETDEV_DOWN:
	case NETDEV_UP:
	case NETDEV_PRE_UP:
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

static struct notifier_block ovpn_netdev_notifier = {
	.notifier_call = ovpn_netdev_notifier_call,
};

static int __init ovpn_init(void)
{
	int err = register_netdevice_notifier(&ovpn_netdev_notifier);

	if (err) {
		pr_err("ovpn: can't register netdevice notifier: %d\n", err);
		return err;
	}

	err = rtnl_link_register(&ovpn_link_ops);
	if (err) {
		pr_err("ovpn: can't register rtnl link ops: %d\n", err);
		goto unreg_netdev;
	}

	err = ovpn_nl_register();
	if (err) {
		pr_err("ovpn: can't register netlink family: %d\n", err);
		goto unreg_rtnl;
	}

	return 0;

unreg_rtnl:
	rtnl_link_unregister(&ovpn_link_ops);
unreg_netdev:
	unregister_netdevice_notifier(&ovpn_netdev_notifier);
	return err;
}

static __exit void ovpn_cleanup(void)
{
	ovpn_nl_unregister();
	rtnl_link_unregister(&ovpn_link_ops);
	unregister_netdevice_notifier(&ovpn_netdev_notifier);

	rcu_barrier();
}

module_init(ovpn_init);
module_exit(ovpn_cleanup);

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
