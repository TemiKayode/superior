// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * The Linux Driver Environment's kernel: the Linux functions every hosted
 * driver calls, for one PCI device, over the Rust host (lde/host.h); the
 * network interface's are in lde-net.c, DRM's in lde-drm.c. Written for
 * Superior; nothing here is Linux's.
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

int sprintf(char *buf, const char *fmt, ...)
{
	struct out o = { .n = 0 };
	__builtin_va_list ap;
	__builtin_va_start(ap, fmt);
	format(&o, fmt, ap);
	__builtin_va_end(ap);
	memcpy(buf, o.buf, o.n);
	buf[o.n] = 0;
	return o.n;
}

int snprintf(char *buf, size_t size, const char *fmt, ...)
{
	struct out o = { .n = 0 };
	__builtin_va_list ap;
	__builtin_va_start(ap, fmt);
	format(&o, fmt, ap);
	__builtin_va_end(ap);
	if (size) {
		size_t n = o.n < size - 1 ? o.n : size - 1;
		memcpy(buf, o.buf, n);
		buf[n] = 0;
	}
	return o.n;
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

void *kcalloc(size_t n, size_t size, gfp_t gfp)
{
	(void)gfp;
	return size && n > (size_t)-1 / size ? NULL : lde_host_alloc(n * size);
}

void kfree(const void *p)
{
	if (p)
		lde_host_free(p);
}

char *strcpy(char *dst, const char *src)
{
	char *d = dst;
	while ((*d++ = *src++))
		;
	return dst;
}

int strcmp(const char *a, const char *b)
{
	for (; *a && *a == *b; a++, b++)
		;
	return (unsigned char)*a - (unsigned char)*b;
}

char *strncpy(char *dst, const char *src, size_t n)
{
	size_t i = 0;
	for (; i < n && src[i]; i++)
		dst[i] = src[i];
	for (; i < n; i++)
		dst[i] = 0;
	return dst;
}

/* ---- timers and work: run by lde_tick, from the component's loop */

static struct timer_list *timers;
static struct work_struct *works;

void timer_setup(struct timer_list *t, void (*function)(struct timer_list *), unsigned int flags)
{
	(void)flags;
	t->function = function;
	t->lde_pending = false;
	t->lde_next = NULL;
}

int del_timer_sync(struct timer_list *t)
{
	bool was = t->lde_pending;
	for (struct timer_list **at = &timers; *at; at = &(*at)->lde_next) {
		if (*at == t) {
			*at = t->lde_next;
			break;
		}
	}
	t->lde_pending = false;
	t->lde_next = NULL;
	return was;
}

int mod_timer(struct timer_list *t, unsigned long expires)
{
	int was = del_timer_sync(t);
	t->expires = expires;
	t->lde_pending = true;
	t->lde_next = timers;
	timers = t;
	return was;
}

bool schedule_work(struct work_struct *work)
{
	if (work->lde_pending)
		return false;
	work->lde_pending = true;
	work->lde_next = works;
	works = work;
	return true;
}

bool cancel_work_sync(struct work_struct *work)
{
	bool was = work->lde_pending;
	for (struct work_struct **at = &works; *at; at = &(*at)->lde_next) {
		if (*at == work) {
			*at = work->lde_next;
			break;
		}
	}
	work->lde_pending = false;
	return was;
}

/* Ticks until the next timer is due (1 if one is, or work waits); 0 if
 * there is nothing to wake for. */
unsigned long lde_next_timer(void)
{
	unsigned long now = jiffies, soonest = 0;
	if (works)
		return 1;
	for (struct timer_list *t = timers; t; t = t->lde_next) {
		unsigned long in = time_after(t->expires, now) ? t->expires - now : 1;
		if (!soonest || in < soonest)
			soonest = in;
	}
	return soonest;
}

void lde_run_timers(void)
{
	/* One at a time, from the list's head each time: what runs may set
	 * or delete any timer. */
	for (;;) {
		struct timer_list *due = NULL;
		for (struct timer_list *t = timers; t; t = t->lde_next)
			if (!time_after(t->expires, jiffies))
				due = t;
		if (!due)
			break;
		del_timer_sync(due);
		due->function(due);
	}
	while (works) {
		struct work_struct *w = works;
		works = w->lde_next;
		w->lde_pending = false;
		w->func(w);
	}
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
	device.devfn = location & 0xff;
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
			/* An I/O BAR: the port the bus server gave it. Its size is
			 * the bus server's to know (it refuses ports past the end);
			 * no I/O BAR is larger than 256 ports. */
			device.resource[bar].start = low & ~3u;
			device.resource[bar].len = 256;
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

/* ---- ports: those of the device's I/O BARs, through the bus server */

/* The I/O BAR `port` lies in (the one starting nearest below it), or -1. */
static int port_bar(unsigned long port, unsigned int *offset)
{
	int found = -1;
	for (int bar = 0; bar < 6; bar++) {
		resource_size_t start = device.resource[bar].start;
		if ((device.resource[bar].flags & IORESOURCE_IO) && port >= start &&
		    port - start < device.resource[bar].len &&
		    (found < 0 || start > device.resource[found].start))
			found = bar;
	}
	if (found < 0)
		lde_once(_printk("the driver reached for I/O port %lx, which it cannot have\n", port));
	else
		*offset = port - device.resource[found].start;
	return found;
}

static u32 port_in(unsigned long port, unsigned int width)
{
	unsigned int offset;
	int bar = port_bar(port, &offset);
	u32 v;
	if (bar < 0 || lde_host_io(bar, offset, width, 0, 0, &v))
		return width == 4 ? ~0u : (1u << 8 * width) - 1;
	return v;
}

static void port_out(unsigned long port, unsigned int width, u32 v)
{
	unsigned int offset;
	int bar = port_bar(port, &offset);
	if (bar >= 0)
		lde_host_io(bar, offset, width, 1, v, NULL);
}

u8 inb(unsigned long port) { return port_in(port, 1); }
u16 inw(unsigned long port) { return port_in(port, 2); }
u32 inl(unsigned long port) { return port_in(port, 4); }
void outb(u8 v, unsigned long port) { port_out(port, 1, v); }
void outw(u16 v, unsigned long port) { port_out(port, 2, v); }
void outl(u32 v, unsigned long port) { port_out(port, 4, v); }

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

/* What the device can address, as its driver said. */
static u64 dma_mask = ~0ull;

int dma_set_mask(struct device *dev, u64 mask)
{
	(void)dev;
	dma_mask = mask;
	return 0;
}

dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size, enum dma_data_direction dir)
{
	(void)dev;
	(void)dir;
	dma_addr_t dma = lde_host_dma(ptr, size);
	if (dma != DMA_MAPPING_ERROR && ((dma + size - 1) & ~dma_mask))
		return DMA_MAPPING_ERROR;
	return dma;
}

struct dma_pool {
	size_t size;
};

struct dma_pool *dma_pool_create(const char *name, struct device *dev, size_t size, size_t align, size_t boundary)
{
	struct dma_pool *pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	(void)name;
	(void)dev;
	(void)align; /* the host's blocks are aligned to 64 bytes or a page */
	(void)boundary;
	if (pool)
		pool->size = size;
	return pool;
}

void dma_pool_destroy(struct dma_pool *pool)
{
	kfree(pool);
}

void *dma_pool_zalloc(struct dma_pool *pool, gfp_t gfp, dma_addr_t *dma)
{
	void *p = dma_alloc_coherent(NULL, pool->size, dma, gfp);
	if (p && ((*dma + pool->size - 1) & ~dma_mask)) {
		lde_host_free(p);
		return NULL;
	}
	return p;
}

void dma_pool_free(struct dma_pool *pool, void *va, dma_addr_t dma)
{
	(void)pool;
	(void)dma;
	lde_host_free(va);
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

