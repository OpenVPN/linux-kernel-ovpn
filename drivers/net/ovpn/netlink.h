/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2024 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_NETLINK_H_
#define _NET_OVPN_NETLINK_H_

int ovpn_nl_register(void);
void ovpn_nl_unregister(void);

/**
 * ovpn_nl_notify_del_peer - notify userspace about peer being deleted
 * @peer: the peer being deleted
 *
 * Return: 0 on success or a negative error code otherwise
 */
int ovpn_nl_notify_del_peer(struct ovpn_peer *peer);

/**
 * ovpn_nl_notify_swap_keys - notify userspace peer's key must be renewed
 * @peer: the peer whose key needs to be renewed
 *
 * Return: 0 on success or a negative error code otherwise
 */
int ovpn_nl_notify_swap_keys(struct ovpn_peer *peer);

#endif /* _NET_OVPN_NETLINK_H_ */
