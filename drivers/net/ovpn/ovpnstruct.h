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

#include <net/gro_cells.h>
#include <uapi/linux/ovpn.h>

/**
 * struct ovpn_peer_collection - container of peers for MultiPeer mode
 * @by_id: table of peers index by ID
 * @by_transp_addr: table of peers indexed by transport address
 * @by_vpn_addr: table of peers indexed by VPN IP address
 * @lock: protects writes to peers tables
 */
struct ovpn_peer_collection {
	DECLARE_HASHTABLE(by_id, 12);
	DECLARE_HASHTABLE(by_transp_addr, 12);
	DECLARE_HASHTABLE(by_vpn_addr, 12);
	spinlock_t lock; /* protects writes to peers tables */
};

/**
 * struct ovpn_struct - per ovpn interface state
 * @dev: the actual netdev representing the tunnel
 * @registered: whether dev is still registered with netdev or not
 * @mode: device operation mode (i.e. p2p, mp, ..)
 * @lock: protect this object
 * @peers: data structures holding multi-peer references
 * @peer: in P2P mode, this is the only remote peer
 * @dev_list: entry for the module wide device list
 * @gro_cells: pointer to the Generic Receive Offload cell
 */
struct ovpn_struct {
	struct net_device *dev;
	bool registered;
	enum ovpn_mode mode;
	spinlock_t lock; /* protect writing to the ovpn_struct object */
	struct ovpn_peer_collection *peers;
	struct ovpn_peer __rcu *peer;
	struct list_head dev_list;
	struct gro_cells gro_cells;
};

#endif /* _NET_OVPN_OVPNSTRUCT_H_ */
