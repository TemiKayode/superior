// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * The Linux Driver Environment's kernel: the Linux functions a hosted
 * driver calls, for one PCI device and one network interface, over the
 * Rust host (lde/host.h). Written for Superior; nothing here is Linux's.
 */
#include <lde/host.h>

/* ---- printing */

struct out {
	char buf[240];
	unsigned int n;
};

static void put(struct out *o, char c)
{
	if (o->n < sizeof(o->buf))
		o->buf[o->n++] = c;
}

static void put_number(struct out *o, u64 v, unsigned int base, bool upper, bool negative,
		       int width, bool zero, bool left)
{
	char digits[24];
	int n = 0;
	do {
		unsigned int d = v % base;
		digits[n++] = d < 10 ? '0' + d : (upper ? 'A' : 'a') + d - 10;
		v /= base;
	} while (v);
	int pad = width - n - negative;
	if (negative && zero)
		put(o, '-');
	if (!left)
		for (; pad > 0; pad--)
			put(o, zero ? '0' : ' ');
	if (negative && !zero)
		put(o, '-');
	while (n)
		put(o, digits[--n]);
	for (; pad > 0; pad--)
		put(o, ' ');
}

/* printf as drivers use it: %c %s %d %i %u %x %X %p, the l, ll, L, z and h
 * lengths, a width, `0` and `-`; and %pM, a MAC address. */
static void format(struct out *o, const char *fmt, __builtin_va_list ap)
{
	for (; *fmt; fmt++) {
		if (*fmt != '%') {
			put(o, *fmt);
			continue;
		}
		bool zero = false, left = false;
		int width = 0, longs = 0;
		for (fmt++; *fmt == '0' || *fmt == '-' || *fmt == '#' || *fmt == ' '; fmt++) {
			zero |= *fmt == '0';
			left |= *fmt == '-';
		}
		for (; *fmt >= '0' && *fmt <= '9'; fmt++)
			width = width * 10 + *fmt - '0';
		for (;; fmt++) {
			if (*fmt == 'l' || *fmt == 'z')
				longs++;
			else if (*fmt == 'L')
				longs = 2;
			else if (*fmt != 'h')
				break;
		}
		switch (*fmt) {
		case 'c':
			put(o, (char)__builtin_va_arg(ap, int));
			break;
		case 's': {
			const char *s = __builtin_va_arg(ap, const char *);
			int pad = width - (int)strlen(s ? s : "(null)");
			for (; !left && pad > 0; pad--)
				put(o, ' ');
			for (s = s ? s : "(null)"; *s; s++)
				put(o, *s);
			for (; pad > 0; pad--)
				put(o, ' ');
			break;
		}
		case 'd':
		case 'i': {
			s64 v = longs ? __builtin_va_arg(ap, long) : __builtin_va_arg(ap, int);
			put_number(o, v < 0 ? -(u64)v : (u64)v, 10, false, v < 0, width, zero, left);
			break;
		}
		case 'u':
		case 'x':
		case 'X': {
			u64 v = longs ? __builtin_va_arg(ap, unsigned long) : __builtin_va_arg(ap, unsigned int);
			put_number(o, v, *fmt == 'u' ? 10 : 16, *fmt == 'X', false, width, zero, left);
			break;
		}
		case 'p': {
			const u8 *p = __builtin_va_arg(ap, const u8 *);
			if (fmt[1] == 'M') {
				fmt++;
				for (int i = 0; i < ETH_ALEN; i++) {
					if (i)
						put(o, ':');
					put_number(o, p[i], 16, false, false, 2, true, false);
				}
			} else {
				/* As Linux prints one: bare hexadecimal. */
				put_number(o, (uintptr_t)p, 16, false, false, 0, false, false);
			}
			break;
		}
		case 0:
			return;
		default:
			put(o, *fmt);
		}
	}
}

int _printk(const char *fmt, ...)
{
	/* Drivers print some lines in pieces: one goes out at its newline. */
	static struct out line;
	__builtin_va_list ap;
	__builtin_va_start(ap, fmt);
	format(&line, fmt, ap);
	__builtin_va_end(ap);
	unsigned int start = 0;
	for (unsigned int i = 0; i < line.n; i++) {
		if (line.buf[i] == '\n') {
			lde_host_log(line.buf + start, i - start);
			start = i + 1;
		}
	}
	if (start == 0 && line.n == sizeof(line.buf)) {
		lde_host_log(line.buf, line.n);
		start = line.n;
	}
	memcpy(line.buf, line.buf + start, line.n - start);
	line.n -= start;
	return 0;
}

void lde_bug(const char *file, int line)
{
	_printk("BUG at %s:%d: the driver cannot go on\n", file, line);
	for (;;)
		lde_host_sleep(1000);
}

/* ---- memory, time */

void *kmalloc(size_t size, gfp_t gfp)
{
	(void)gfp;
	return lde_host_alloc(size);
}

void *kzalloc(size_t size, gfp_t gfp)
{
	(void)gfp;
	return lde_host_alloc(size);
}

void kfree(const void *p)
{
	if (p)
		lde_host_free(p);
}

ssize_t strscpy(char *dst, const char *src, size_t size)
{
	size_t n = 0;
	if (!size)
		return -1;
	for (; n + 1 < size && src[n]; n++)
		dst[n] = src[n];
	dst[n] = 0;
	return src[n] ? -1 : (ssize_t)n;
}

void udelay(unsigned long usecs)
{
	lde_host_udelay(usecs);
}

void mdelay(unsigned long msecs)
{
	lde_host_udelay(msecs * 1000);
}

void msleep(unsigned int msecs)
{
	lde_host_sleep((msecs * HZ + 999) / 1000);
}

long schedule_timeout_uninterruptible(long timeout)
{
	lde_host_sleep(timeout);
	return 0;
}

/* ---- PCI: one device, the one the host opened */

static struct pci_driver *driver;
static struct pci_dev device;
static char device_name[16];

int pci_register_driver(struct pci_driver *drv)
{
	driver = drv;
	return 0;
}

void pci_unregister_driver(struct pci_driver *drv)
{
	if (driver == drv)
		driver = NULL;
}

int lde_device_id(unsigned int i, u16 *vendor, u16 *dev)
{
	if (!driver)
		return 0;
	for (const struct pci_device_id *id = driver->id_table; id->vendor; id++) {
		if (i-- == 0) {
			*vendor = id->vendor;
			*dev = id->device;
			return 1;
		}
	}
	return 0;
}

int lde_probe(u16 vendor, u16 dev, u32 bars)
{
	const struct pci_device_id *id;
	u32 subsystem = lde_host_config_read(0x2c);
	u32 location = lde_host_location();

	if (!driver)
		return -ENODEV;
	for (id = driver->id_table; id->vendor; id++)
		if (id->vendor == vendor && id->device == dev)
			break;
	if (!id->vendor)
		return -ENODEV;
	memset(&device, 0, sizeof(device));
	struct out name = { .n = 0 };
	put_number(&name, location >> 8, 16, false, false, 2, true, false);
	put(&name, ':');
	put_number(&name, location >> 3 & 0x1f, 16, false, false, 2, true, false);
	put(&name, '.');
	put_number(&name, location & 7, 16, false, false, 0, false, false);
	memcpy(device_name, name.buf, name.n);
	device_name[name.n] = 0;
	device.dev.name = device_name;
	device.vendor = vendor;
	device.device = dev;
	device.subsystem_vendor = subsystem & 0xffff;
	device.subsystem_device = subsystem >> 16;
	device.revision = lde_host_config_read(0x08) & 0xff;
	/* The line's number means nothing here: there is one, the host's. */
	device.irq = 1;
	device.driver = driver;
	for (unsigned int bar = 0; bar < 6; bar++) {
		u32 low = lde_host_config_read(0x10 + 4 * bar);
		if (bars & 1u << bar) {
			device.resource[bar].start = low & ~0xfull;
			if ((low & 6) == 4)
				device.resource[bar].start |= (u64)lde_host_config_read(0x14 + 4 * bar) << 32;
			device.resource[bar].len = lde_host_bar_size(bar);
			device.resource[bar].flags = IORESOURCE_MEM;
		} else if (low & 1) {
			/* An I/O BAR: there, but never assigned. */
			device.resource[bar].flags = IORESOURCE_IO;
		}
	}
	return driver->probe(&device, id);
}

int pci_enable_device(struct pci_dev *dev)
{
	(void)dev; /* the bus server enabled its memory when it was opened */
	return 0;
}

void pci_disable_device(struct pci_dev *dev)
{
	(void)dev;
	lde_host_bus_master(0);
}

int pci_request_regions(struct pci_dev *dev, const char *name)
{
	(void)dev; /* the function is this component's alone */
	(void)name;
	return 0;
}

void pci_release_regions(struct pci_dev *dev)
{
	(void)dev;
}

void pci_set_master(struct pci_dev *dev)
{
	if (lde_host_bus_master(1))
		dev_err(&dev->dev, "the bus server refused bus mastering\n");
}

int pci_read_config_word(struct pci_dev *dev, int where, u16 *val)
{
	(void)dev;
	*val = lde_host_config_read(where & ~3) >> (8 * (where & 3));
	return 0;
}

int pci_write_config_word(struct pci_dev *dev, int where, u16 val)
{
	/* The bus server lets a driver write no configuration register. */
	dev_dbg(&dev->dev, "configuration write %x = %x ignored\n", where, val);
	return 0;
}

void __iomem *pci_iomap(struct pci_dev *dev, int bar, unsigned long max)
{
	(void)max;
	if (bar < 0 || bar >= 6 || !(dev->resource[bar].flags & IORESOURCE_MEM))
		return NULL;
	return lde_host_bar_map(bar);
}

void __iomem *ioremap(resource_size_t phys, size_t size)
{
	for (unsigned int bar = 0; bar < 6; bar++) {
		resource_size_t start = device.resource[bar].start;
		if ((device.resource[bar].flags & IORESOURCE_MEM) && phys >= start &&
		    phys + size <= start + device.resource[bar].len) {
			u8 *base = lde_host_bar_map(bar);
			return base ? base + (phys - start) : NULL;
		}
	}
	return NULL;
}

/* ---- DMA */

void *dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma, gfp_t gfp)
{
	void *p = lde_host_alloc(size);
	(void)dev;
	(void)gfp;
	if (!p)
		return NULL;
	*dma = lde_host_dma(p, size);
	if (*dma == DMA_MAPPING_ERROR) {
		lde_host_free(p);
		return NULL;
	}
	return p;
}

void dma_free_coherent(struct device *dev, size_t size, void *va, dma_addr_t dma)
{
	(void)dev;
	(void)size;
	(void)dma;
	lde_host_free(va);
}

dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size, enum dma_data_direction dir)
{
	(void)dev;
	(void)dir;
	return lde_host_dma(ptr, size);
}

/* ---- the interrupt */

static irq_handler_t handler;
static void *handler_dev;

int request_irq(unsigned int irq, irq_handler_t h, unsigned long flags, const char *name, void *dev)
{
	(void)irq;
	(void)flags;
	(void)name;
	handler = h;
	handler_dev = dev;
	int rc = lde_host_irq(1);
	if (rc)
		handler = NULL;
	return rc;
}

void free_irq(unsigned int irq, void *dev)
{
	(void)irq;
	(void)dev;
	handler = NULL;
	lde_host_irq(0);
}

void lde_interrupt(void)
{
	if (handler)
		handler(device.irq, handler_dev);
}

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

/* The transmit watchdog: a queue the driver stopped and has not woken
 * for `watchdog_timeo` is reported to it. */
void lde_tick(void)
{
	struct net_device *dev = netdev;
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
