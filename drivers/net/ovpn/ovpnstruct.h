/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2024 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNSTRUCT_H_
#define _NET_OVPN_OVPNSTRUCT_H_

#include <uapi/linux/ovpn.h>

/**
 * struct ovpn_struct - per ovpn interface state
 * @dev: the actual netdev representing the tunnel
 * @registered: whether dev is still registered with netdev or not
 * @mode: device operation mode (i.e. p2p, mp, ..)
 * @dev_list: entry for the module wide device list
 */
struct ovpn_struct {
	struct net_device *dev;
	bool registered;
	enum ovpn_mode mode;
	struct list_head dev_list;
};

#endif /* _NET_OVPN_OVPNSTRUCT_H_ */
