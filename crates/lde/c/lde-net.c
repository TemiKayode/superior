// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * The Linux Driver Environment's network half: one network interface,
 * NAPI, socket buffers and MII, for a hosted network driver, over the
 * Rust host (lde/host.h). Written for Superior; nothing here is Linux's.
 */
#include <lde/host.h>

/* ---- the network interface: one */

static struct net_device *netdev;
static struct napi_struct *napis;

struct net_device *alloc_etherdev(int sizeof_priv)
{
	size_t priv = ALIGN(sizeof(struct net_device), 64);
	struct net_device *dev = lde_host_alloc(priv + sizeof_priv);
	if (!dev)
		return NULL;
	dev->lde_priv = (char *)dev + priv;
	dev->dev_addr = dev->lde_addr;
	dev->mtu = ETH_DATA_LEN;
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = ETH_DATA_LEN;
	dev->lde_present = true;
	memcpy(dev->name, "eth%d", 6);
	return dev;
}

void free_netdev(struct net_device *dev)
{
	if (netdev == dev)
		netdev = NULL;
	lde_host_free(dev);
}

int register_netdev(struct net_device *dev)
{
	if (netdev)
		return -EBUSY;
	memcpy(dev->name, "eth0", 5);
	dev->dev.name = dev->name;
	netdev = dev;
	return 0;
}

void unregister_netdev(struct net_device *dev)
{
	if (dev->lde_running) {
		dev->lde_running = false;
		dev->netdev_ops->ndo_stop(dev);
	}
	if (netdev == dev)
		netdev = NULL;
}

int lde_open(void)
{
	if (!netdev)
		return -ENODEV;
	if (netdev->netdev_ops->ndo_validate_addr) {
		int rc = netdev->netdev_ops->ndo_validate_addr(netdev);
		if (rc)
			return rc;
	}
	/* The `nic` interface has no way to ask for a multicast group (IPv6
	 * needs several): the driver is told to take all multicast. */
	netdev->flags |= IFF_ALLMULTI;
	/* Linux marks the interface running before the driver's open. */
	netdev->lde_running = true;
	int rc = netdev->netdev_ops->ndo_open(netdev);
	if (rc)
		netdev->lde_running = false;
	else if (netdev->netdev_ops->ndo_set_rx_mode)
		netdev->netdev_ops->ndo_set_rx_mode(netdev);
	return rc;
}

int eth_validate_addr(struct net_device *dev)
{
	return is_valid_ether_addr(dev->dev_addr) ? 0 : -EINVAL;
}

void eth_hw_addr_set(struct net_device *dev, const u8 *addr)
{
	memcpy(dev->lde_addr, addr, ETH_ALEN);
}

void lde_mac(u8 *mac)
{
	memset(mac, 0, ETH_ALEN);
	if (netdev)
		memcpy(mac, netdev->dev_addr, ETH_ALEN);
}

int lde_carrier(void)
{
	return netdev && netdev->lde_carrier;
}

void netif_carrier_on(struct net_device *dev)
{
	dev->lde_carrier = true;
}

void netif_carrier_off(struct net_device *dev)
{
	dev->lde_carrier = false;
}

void netif_stop_queue(struct net_device *dev)
{
	if (!dev->lde_stopped)
		dev->lde_stopped_at = jiffies;
	dev->lde_stopped = true;
}

void netif_wake_queue(struct net_device *dev)
{
	dev->lde_stopped = false;
}

u32 ethtool_op_get_link(struct net_device *dev)
{
	return dev->lde_carrier;
}

int ethtool_op_get_ts_info(struct net_device *dev, struct ethtool_ts_info *info)
{
	(void)dev;
	(void)info;
	return -EOPNOTSUPP;
}

/* The driver's timers and work that are due; and the transmit watchdog:
 * a queue the driver stopped and has not woken for `watchdog_timeo` is
 * reported to it. */
void lde_tick(void)
{
	struct net_device *dev = netdev;
	lde_run_timers();
	if (!dev || !dev->lde_running || !dev->lde_stopped || !dev->lde_carrier)
		return;
	if (dev->watchdog_timeo <= 0 || !dev->netdev_ops->ndo_tx_timeout)
		return;
	if (time_after(jiffies, dev->lde_stopped_at + dev->watchdog_timeo)) {
		netdev_warn(dev, "transmit queue stopped for %d ticks: telling the driver\n",
			    dev->watchdog_timeo);
		dev->lde_stopped_at = jiffies;
		dev->netdev_ops->ndo_tx_timeout(dev, 0);
	}
}

/* ---- NAPI */

void netif_napi_add_weight(struct net_device *dev, struct napi_struct *napi,
			   int (*poll)(struct napi_struct *, int), int weight)
{
	napi->poll = poll;
	napi->weight = weight;
	napi->dev = dev;
	napi->enabled = false;
	napi->scheduled = false;
	napi->next = napis;
	napis = napi;
}

void napi_enable(struct napi_struct *napi)
{
	napi->enabled = true;
	napi->scheduled = false;
}

void napi_disable(struct napi_struct *napi)
{
	napi->enabled = false;
	napi->scheduled = false;
}

bool napi_schedule_prep(struct napi_struct *napi)
{
	if (!napi->enabled || napi->scheduled)
		return false;
	napi->scheduled = true;
	return true;
}

bool napi_complete_done(struct napi_struct *napi, int work_done)
{
	(void)work_done;
	napi->scheduled = false;
	return true;
}

int lde_poll_pending(void)
{
	for (struct napi_struct *n = napis; n; n = n->next)
		if (n->enabled && n->scheduled)
			return 1;
	return 0;
}

int lde_poll_weight(void)
{
	int most = 1;
	for (struct napi_struct *n = napis; n; n = n->next)
		most = max(most, n->weight);
	return most;
}

void lde_poll(void)
{
	for (struct napi_struct *n = napis; n; n = n->next)
		if (n->enabled && n->scheduled)
			n->poll(n, n->weight);
}

/* ---- socket buffers */

/* Room in front of a frame, as Linux leaves. */
#define HEADROOM 32

struct sk_buff *alloc_skb(unsigned int size, gfp_t gfp)
{
	struct sk_buff *skb = kzalloc(sizeof(*skb), gfp);
	if (!skb)
		return NULL;
	skb->head = lde_host_alloc(size);
	if (!skb->head) {
		kfree(skb);
		return NULL;
	}
	skb->data = skb->head;
	skb->lde_size = size;
	return skb;
}

struct sk_buff *netdev_alloc_skb_ip_align(struct net_device *dev, unsigned int length)
{
	struct sk_buff *skb = alloc_skb(length + HEADROOM, GFP_ATOMIC);
	if (skb) {
		skb_reserve(skb, HEADROOM);
		skb->dev = dev;
	}
	return skb;
}

struct sk_buff *napi_alloc_skb(struct napi_struct *napi, unsigned int length)
{
	return netdev_alloc_skb_ip_align(napi->dev, length);
}

void kfree_skb(struct sk_buff *skb)
{
	if (!skb)
		return;
	lde_host_free(skb->head);
	kfree(skb);
}

void *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tail = skb->data + skb->len;
	BUG_ON(tail + len > skb->head + skb->lde_size);
	skb->len += len;
	return tail;
}

__be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{
	const struct ethhdr *eth = (const struct ethhdr *)skb->data;
	skb->dev = dev;
	skb->lde_mac_header = skb->data;
	skb->data += ETH_HLEN;
	skb->len -= ETH_HLEN;
	return ntohs(eth->h_proto) >= ETH_P_802_3_MIN ? eth->h_proto : htons(ETH_P_802_2);
}

/* A frame from the driver: to the host, whole, and the buffer is free. */
int netif_receive_skb(struct sk_buff *skb)
{
	if (skb->lde_mac_header)
		lde_host_rx(skb->lde_mac_header, skb->len + ETH_HLEN);
	kfree_skb(skb);
	return 0;
}

int lde_xmit(const void *frame, size_t len)
{
	struct net_device *dev = netdev;
	if (!dev || !dev->lde_running)
		return -ENETDOWN;
	if (dev->lde_stopped)
		return 1;
	/* Short frames go out padded to the Ethernet minimum. */
	unsigned int size = max_t(unsigned int, len, ETH_ZLEN);
	struct sk_buff *skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	memcpy(skb_put(skb, size), frame, len);
	skb->dev = dev;
	skb->protocol = ((const struct ethhdr *)frame)->h_proto;
	skb->ip_summed = CHECKSUM_NONE;
	if (dev->netdev_ops->ndo_start_xmit(skb, dev) != NETDEV_TX_OK) {
		/* The driver did not take it: it is still ours. */
		kfree_skb(skb);
		return 1;
	}
	return 0;
}

/* ---- MII */

unsigned int mii_check_media(struct mii_if_info *mii, unsigned int ok_to_print, unsigned int init_media)
{
	struct net_device *dev = mii->dev;
	bool had = netif_carrier_ok(dev);
	/* The link bit latches a loss: read it twice. */
	mii->mdio_read(dev, mii->phy_id, MII_BMSR);
	bool has = mii->mdio_read(dev, mii->phy_id, MII_BMSR) & BMSR_LSTATUS;
	if (!has) {
		if (had) {
			netif_carrier_off(dev);
			if (ok_to_print)
				netdev_info(dev, "link down\n");
		}
		return 0;
	}
	if (had && !init_media)
		return 0;
	netif_carrier_on(dev);
	int common = mii->mdio_read(dev, mii->phy_id, MII_ADVERTISE) & mii->mdio_read(dev, mii->phy_id, MII_LPA);
	bool fast = common & (LPA_100FULL | LPA_100HALF | LPA_100BASE4);
	unsigned int duplex = mii->force_media ? mii->full_duplex :
		(common & LPA_100FULL) || (common & (LPA_100HALF | LPA_10FULL)) == LPA_10FULL;
	if (ok_to_print)
		netdev_info(dev, "link up, %uMbps, %s-duplex\n", fast ? 100 : 10, duplex ? "full" : "half");
	bool changed = init_media || mii->full_duplex != duplex;
	mii->full_duplex = duplex;
	return changed;
}

int mii_link_ok(struct mii_if_info *mii)
{
	mii->mdio_read(mii->dev, mii->phy_id, MII_BMSR);
	return !!(mii->mdio_read(mii->dev, mii->phy_id, MII_BMSR) & BMSR_LSTATUS);
}

void mii_check_link(struct mii_if_info *mii)
{
	bool has = mii_link_ok(mii);
	if (has && !netif_carrier_ok(mii->dev))
		netif_carrier_on(mii->dev);
	else if (!has && netif_carrier_ok(mii->dev))
		netif_carrier_off(mii->dev);
}

/* The link as negotiated: what both ends advertise. */
void mii_ethtool_gset(struct mii_if_info *mii, struct ethtool_cmd *cmd)
{
	struct net_device *dev = mii->dev;
	int bmcr = mii->mdio_read(dev, mii->phy_id, MII_BMCR);
	cmd->phy_address = mii->phy_id;
	cmd->speed_hi = 0;
	if (bmcr & BMCR_ANENABLE) {
		int common = mii->mdio_read(dev, mii->phy_id, MII_ADVERTISE) &
			     mii->mdio_read(dev, mii->phy_id, MII_LPA);
		cmd->autoneg = AUTONEG_ENABLE;
		cmd->speed = common & (LPA_100FULL | LPA_100HALF | LPA_100BASE4) ? SPEED_100 : SPEED_10;
		cmd->duplex = (common & LPA_100FULL) || (common & (LPA_100HALF | LPA_10FULL)) == LPA_10FULL ?
			DUPLEX_FULL : DUPLEX_HALF;
	} else {
		cmd->autoneg = AUTONEG_DISABLE;
		cmd->speed = bmcr & BMCR_SPEED100 ? SPEED_100 : SPEED_10;
		cmd->duplex = bmcr & BMCR_FULLDPLX ? DUPLEX_FULL : DUPLEX_HALF;
	}
	mii->full_duplex = cmd->duplex == DUPLEX_FULL;
}

int mii_ethtool_sset(struct mii_if_info *mii, struct ethtool_cmd *cmd)
{
	(void)mii;
	(void)cmd;
	return -EOPNOTSUPP;
}

int mii_nway_restart(struct mii_if_info *mii)
{
	int bmcr = mii->mdio_read(mii->dev, mii->phy_id, MII_BMCR);
	if (!(bmcr & BMCR_ANENABLE))
		return -EINVAL;
	mii->mdio_write(mii->dev, mii->phy_id, MII_BMCR, bmcr | BMCR_ANRESTART);
	return 0;
}

/* ethtool and the MII ioctls have no caller here yet. */
void mii_ethtool_get_link_ksettings(struct mii_if_info *mii, struct ethtool_link_ksettings *cmd)
{
	(void)mii;
	(void)cmd;
}

int mii_ethtool_set_link_ksettings(struct mii_if_info *mii, const struct ethtool_link_ksettings *cmd)
{
	(void)mii;
	(void)cmd;
	return -EOPNOTSUPP;
}

int generic_mii_ioctl(struct mii_if_info *mii, struct mii_ioctl_data *data, int cmd, unsigned int *duplex_changed)
{
	(void)mii;
	(void)data;
	(void)cmd;
	(void)duplex_changed;
	return -EOPNOTSUPP;
}

/* The Ethernet CRC as multicast filters hash with it: most significant
 * bit first, not complemented at the end. */
u32 ether_crc(int length, unsigned char *data)
{
	u32 crc = ~0u;
	while (length-- > 0) {
		u8 byte = *data++;
		for (int bit = 0; bit < 8; bit++, byte >>= 1)
			crc = (crc << 1) ^ (((crc >> 31) ^ (byte & 1)) ? 0x04c11db7 : 0);
	}
	return crc;
}
