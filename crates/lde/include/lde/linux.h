/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * The Linux Driver Environment: the part of the Linux kernel's API that
 * the hosted drivers use, written for Superior. Nothing here comes from
 * Linux: the names and meanings are Linux's (so its drivers compile
 * unchanged), the implementation is this environment's, in lde.c and, for
 * what touches the system, in the Rust host (crates/lde/src/lib.rs).
 *
 * Every <linux/...> and <asm/...> header a driver includes is this file.
 *
 * The environment is one thread: the driver's interrupt handler, its
 * NAPI poll and its transmit routine are called one after another from
 * the component's loop, never at once. So locks are empty, and "interrupt
 * context" is an ordinary call.
 */
#ifndef LDE_LINUX_H
#define LDE_LINUX_H

/* ---- types */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef short s16;
typedef int s32;
typedef long long s64;
typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;
typedef u16 __le16;
typedef u32 __le32;
typedef u64 __le64;
typedef u16 __be16;
typedef u32 __be32;
typedef u16 __sum16;
typedef _Bool bool;
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long uintptr_t;
typedef u64 dma_addr_t;
typedef u64 resource_size_t;
typedef u64 phys_addr_t;
typedef unsigned int gfp_t;
typedef u64 netdev_features_t;
typedef int irqreturn_t;
typedef int netdev_tx_t;
typedef long long loff_t;
typedef u8 uint8_t;
typedef u16 uint16_t;
typedef u32 uint32_t;
typedef u64 uint64_t;

#define true 1
#define false 0
#define NULL ((void *)0)

/* ---- the compiler */

#define __iomem
#define __user
#define __force
#define __init
#define __exit
#define __maybe_unused __attribute__((unused))
#define __always_unused __attribute__((unused))
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define __printf(a, b) __attribute__((format(printf, a, b)))
#define ____cacheline_aligned __attribute__((aligned(64)))
#define __read_mostly
#define noinline __attribute__((noinline))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define barrier() __asm__ __volatile__("" : : : "memory")
#define offsetof(type, member) __builtin_offsetof(type, member)
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BIT(n) (1UL << (n))
#define ALIGN(x, a) (((x) + (a) - 1) & ~((__typeof__(x))(a) - 1))
#define min(a, b) ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a < _b ? _a : _b; })
#define max(a, b) ({ __typeof__(a) _a = (a); __typeof__(b) _b = (b); _a > _b ? _a : _b; })
#define min_t(t, a, b) ({ t _a = (a); t _b = (b); _a < _b ? _a : _b; })
#define max_t(t, a, b) ({ t _a = (a); t _b = (b); _a > _b ? _a : _b; })
#define __stringify_1(x) #x
#define __stringify(x) __stringify_1(x)

/* Both machines are little-endian. */
#define cpu_to_le16(x) ((__le16)(x))
#define cpu_to_le32(x) ((__le32)(x))
#define cpu_to_le64(x) ((__le64)(x))
#define le16_to_cpu(x) ((u16)(x))
#define le32_to_cpu(x) ((u32)(x))
#define le64_to_cpu(x) ((u64)(x))
#define swab16(x) __builtin_bswap16((u16)(x))
#define swab32(x) __builtin_bswap32((u32)(x))
#define htons(x) ((__be16)__builtin_bswap16((u16)(x)))
#define ntohs(x) ((u16)__builtin_bswap16((u16)(x)))
#define htonl(x) ((__be32)__builtin_bswap32((u32)(x)))
#define ntohl(x) ((u32)__builtin_bswap32((u32)(x)))
#define cpu_to_be16(x) htons(x)
#define be16_to_cpu(x) ntohs(x)

/* ---- errors */

#define EPERM 1
#define ENOENT 2
#define EIO 5
#define EAGAIN 11
#define ENOMEM 12
#define EFAULT 14
#define EBUSY 16
#define ENODEV 19
#define EINVAL 22
#define ENOSPC 28
#define ENOSYS 38
#define ENODATA 61
#define ENOTSUPP 524
#define EOPNOTSUPP 95
#define EADDRNOTAVAIL 99
#define ENETDOWN 100
#define ETIMEDOUT 110
#define MAX_ERRNO 4095

static inline void *ERR_PTR(long error) { return (void *)error; }
static inline long PTR_ERR(const void *ptr) { return (long)ptr; }
static inline bool IS_ERR(const void *ptr)
{
	return (unsigned long)ptr >= (unsigned long)-MAX_ERRNO;
}
static inline bool IS_ERR_OR_NULL(const void *ptr) { return !ptr || IS_ERR(ptr); }
static inline int PTR_ERR_OR_ZERO(const void *ptr) { return IS_ERR(ptr) ? PTR_ERR(ptr) : 0; }

/* ---- printing (lde.c) */

int _printk(const char *fmt, ...) __printf(1, 2);
int sprintf(char *buf, const char *fmt, ...) __printf(2, 3);
int snprintf(char *buf, size_t size, const char *fmt, ...) __printf(3, 4);
void lde_bug(const char *file, int line) __attribute__((noreturn));

#define KERN_ERR ""
#define KERN_WARNING ""
#define KERN_INFO ""
#define KERN_DEBUG ""
#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif
#define printk(fmt, ...) _printk(fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...) _printk(pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...) _printk(pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) _printk(pr_fmt(fmt), ##__VA_ARGS__)
/* Debug messages are compiled, checked and left out. */
#define lde_no_print(fmt, ...) do { if (0) _printk(fmt, ##__VA_ARGS__); } while (0)
#define pr_debug(fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)
#define lde_once(what) do { static bool _done; if (!_done) { _done = true; what; } } while (0)
#define pr_info_once(fmt, ...) lde_once(pr_info(fmt, ##__VA_ARGS__))

#define BUG() lde_bug(__FILE__, __LINE__)
#define BUG_ON(c) do { if (unlikely(c)) BUG(); } while (0)
#define WARN_ON(c) ({ bool _w = !!(c); if (_w) _printk("warning at %s:%d\n", __FILE__, __LINE__); _w; })
#define WARN_ON_ONCE(c) ({ bool _w = !!(c); if (_w) lde_once(_printk("warning at %s:%d\n", __FILE__, __LINE__)); _w; })
#define WARN_ONCE(c, fmt, ...) ({ bool _w = !!(c); if (_w) lde_once(_printk(fmt, ##__VA_ARGS__)); _w; })

/* ---- strings and memory */

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
ssize_t strscpy(char *dst, const char *src, size_t size);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
static inline void put_unaligned_le32(u32 v, void *p) { memcpy(p, &v, 4); }
static inline u32 get_unaligned_le32(const void *p) { u32 v; memcpy(&v, p, 4); return v; }

#define GFP_KERNEL 0u
#define GFP_ATOMIC 1u
void *kmalloc(size_t size, gfp_t gfp);
void *kzalloc(size_t size, gfp_t gfp);
void *kcalloc(size_t n, size_t size, gfp_t gfp);
void kfree(const void *p);

/* ---- time */

#define HZ 100
unsigned long lde_host_jiffies(void);
#define jiffies lde_host_jiffies()
#define time_after(a, b) ((long)((b) - (a)) < 0)
#define time_before(a, b) time_after(b, a)
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define round_jiffies(j) (j)
#define cpu_relax() barrier()
void udelay(unsigned long usecs);
#define msleep_interruptible(ms) (msleep(ms), 0ul)

/* Kernel timers and work: the component's loop runs what is due between
 * interrupts and calls, on the one thread (lde.c). */
struct timer_list {
	void (*function)(struct timer_list *t);
	unsigned long expires;
	bool lde_pending;
	struct timer_list *lde_next;
};
void timer_setup(struct timer_list *t, void (*function)(struct timer_list *), unsigned int flags);
int mod_timer(struct timer_list *t, unsigned long expires);
int del_timer_sync(struct timer_list *t);
#define del_timer(t) del_timer_sync(t)
#define from_timer(var, t, field) container_of(t, __typeof__(*var), field)
struct work_struct {
	void (*func)(struct work_struct *work);
	bool lde_pending;
	struct work_struct *lde_next;
};
#define INIT_WORK(w, f) do { (w)->func = (f); (w)->lde_pending = false; } while (0)
bool schedule_work(struct work_struct *work);
bool cancel_work_sync(struct work_struct *work);
struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
};
void mdelay(unsigned long msecs);
void msleep(unsigned int msecs);
long schedule_timeout_uninterruptible(long timeout);

/* ---- locks: one thread, so nothing to exclude */

typedef struct { int unused; } spinlock_t;
#define spin_lock_init(l) ((void)(l))
#define spin_lock(l) ((void)(l))
#define spin_unlock(l) ((void)(l))
#define spin_lock_irq(l) ((void)(l))
#define spin_unlock_irq(l) ((void)(l))
#define spin_lock_bh(l) ((void)(l))
#define spin_unlock_bh(l) ((void)(l))
#define spin_lock_irqsave(l, flags) do { (void)(l); (flags) = 0; } while (0)
#define spin_unlock_irqrestore(l, flags) do { (void)(l); (void)(flags); } while (0)
#define rmb() barrier()
#define wmb() lde_host_wmb()
#define mb() lde_host_wmb()
void lde_host_wmb(void);
struct mutex { int unused; };
#define mutex_init(m) ((void)(m))
#define mutex_lock(m) ((void)(m))
#define mutex_unlock(m) ((void)(m))
#define rtnl_lock() do { } while (0)
#define rtnl_unlock() do { } while (0)
#define synchronize_rcu() do { } while (0)

/* ---- modules */

/* No optional part of the kernel is configured in (a driver's joystick
 * port, say): drivers leave out what would use it. */
#define IS_ENABLED(option) 0
#define IS_REACHABLE(option) 0
struct module;
#define THIS_MODULE ((struct module *)0)

#define lde_nothing(tag) struct lde_nothing_##tag
#define lde_nothing_1(line) lde_nothing(line)
#define LDE_NOTHING lde_nothing_1(__LINE__)
#define MODULE_AUTHOR(x) LDE_NOTHING
#define MODULE_DESCRIPTION(x) LDE_NOTHING
#define MODULE_LICENSE(x) LDE_NOTHING
#define MODULE_FIRMWARE(x) LDE_NOTHING
#define MODULE_VERSION(x) LDE_NOTHING
#define MODULE_PARM_DESC(name, x) LDE_NOTHING
#define MODULE_DEVICE_TABLE(bus, table) LDE_NOTHING
#define module_param(name, type, perm) LDE_NOTHING
#define module_param_array(name, type, nump, perm) LDE_NOTHING
#define module_param_named(name, var, type, perm) LDE_NOTHING
/* The host calls these (lde.c) to load the driver. */
#define module_init(fn) int lde_module_init(void) { return fn(); }
#define module_exit(fn) void lde_module_exit(void) { fn(); }

/* ---- devices */

struct pci_dev;
struct device {
	const char *name;
	void *driver_data;
	struct device *parent;
};
struct dev_pm_ops {
	int (*suspend)(struct device *dev);
	int (*resume)(struct device *dev);
};
struct device_driver {
	const char *name;
	const struct dev_pm_ops *pm;
};
/* Power management has no caller yet (Phase 2's suspend and resume). */
#define SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn)
#define SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
	const struct dev_pm_ops __maybe_unused name = { .suspend = suspend_fn, .resume = resume_fn }
static inline void *dev_get_drvdata(const struct device *dev) { return dev->driver_data; }
static inline void dev_set_drvdata(struct device *dev, void *data) { dev->driver_data = data; }
static inline const char *dev_name(const struct device *dev) { return dev->name; }
static inline int device_set_wakeup_enable(struct device *dev, bool on) { (void)dev; (void)on; return 0; }
static inline bool device_can_wakeup(struct device *dev) { (void)dev; return false; }
/* Nothing ever shuts the system down under a driver. */
enum { SYSTEM_RUNNING, SYSTEM_POWER_OFF };
#define system_state SYSTEM_RUNNING

/* Firmware files: there are none to load. */
struct firmware {
	size_t size;
	const u8 *data;
};
static inline int request_firmware(const struct firmware **fw, const char *name, struct device *dev)
{
	(void)name; (void)dev;
	*fw = NULL;
	return -ENOENT;
}
static inline void release_firmware(const struct firmware *fw) { (void)fw; }
#define dev_err(dev, fmt, ...) _printk("%s: " fmt, dev_name(dev), ##__VA_ARGS__)
#define dev_warn(dev, fmt, ...) _printk("%s: " fmt, dev_name(dev), ##__VA_ARGS__)
#define dev_info(dev, fmt, ...) _printk("%s: " fmt, dev_name(dev), ##__VA_ARGS__)
#define dev_dbg(dev, fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)

/* ---- PCI */

#define PCI_ANY_ID (~0u)
#define PCI_VENDOR_ID_REALTEK 0x10ec
#define PCI_DEVICE_ID_REALTEK_8139 0x8139
#define PCI_VENDOR_ID_INTEL 0x8086
#define PCI_VENDOR_ID_ENSONIQ 0x1274
#define PCI_SUBVENDOR_ID_REDHAT_QUMRANET 0x1af4
#define PCI_SUBDEVICE_ID_QEMU 0x1100
#define PCI_CLASS_NETWORK_ETHERNET 0x0200
#define PCI_FUNC(devfn) ((devfn) & 7)
#define PCI_SLOT(devfn) ((devfn) >> 3 & 0x1f)
#define PCI_VENDOR_ID_TTTECH 0x0357
#define PCI_DEVICE_ID_TTTECH_MC322 0x000a
#define PCI_COMMAND 0x04
#define PCI_STATUS 0x06
#define PCI_D0 0
#define PCI_D3hot 3
#define IORESOURCE_IO 0x00000100
#define IORESOURCE_MEM 0x00000200

struct pci_device_id {
	u32 vendor, device, subvendor, subdevice, class, class_mask;
	unsigned long driver_data;
};
#define PCI_DEVICE(vend, dev) \
	.vendor = (vend), .device = (dev), .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
/* As Linux has it, followed by the class and its mask (0). */
#define PCI_VDEVICE(vend, dev) \
	.vendor = PCI_VENDOR_ID_##vend, .device = (dev), .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0

struct pci_driver;
struct pci_dev {
	struct device dev;
	u16 vendor, device, subsystem_vendor, subsystem_device;
	u8 revision;
	unsigned int devfn;
	unsigned int irq;
	struct {
		resource_size_t start, len;
		unsigned long flags;
	} resource[6];
	struct pci_driver *driver;
};
typedef unsigned int pci_ers_result_t;
typedef unsigned int pci_channel_state_t;
enum { PCI_ERS_RESULT_NONE = 1, PCI_ERS_RESULT_CAN_RECOVER, PCI_ERS_RESULT_NEED_RESET,
       PCI_ERS_RESULT_DISCONNECT, PCI_ERS_RESULT_RECOVERED };
enum { pci_channel_io_normal = 1, pci_channel_io_frozen, pci_channel_io_perm_failure };
struct pci_error_handlers {
	pci_ers_result_t (*error_detected)(struct pci_dev *dev, pci_channel_state_t error);
	pci_ers_result_t (*slot_reset)(struct pci_dev *dev);
	void (*resume)(struct pci_dev *dev);
};
struct pci_driver {
	const char *name;
	const struct pci_device_id *id_table;
	int (*probe)(struct pci_dev *dev, const struct pci_device_id *id);
	void (*remove)(struct pci_dev *dev);
	void (*shutdown)(struct pci_dev *dev);
	const struct pci_error_handlers *err_handler;
	struct device_driver driver;
};
#define to_pci_dev(d) container_of(d, struct pci_dev, dev)
static inline void pci_pme_active(struct pci_dev *dev, bool on) { (void)dev; (void)on; }
static inline int pci_prepare_to_sleep(struct pci_dev *dev) { (void)dev; return 0; }
static inline int pci_wake_from_d3(struct pci_dev *dev, bool on) { (void)dev; (void)on; return 0; }
int pci_register_driver(struct pci_driver *drv);
void pci_unregister_driver(struct pci_driver *drv);
#define module_pci_driver(drv) \
	int lde_module_init(void) { return pci_register_driver(&drv); } \
	void lde_module_exit(void) { pci_unregister_driver(&drv); }

int pci_enable_device(struct pci_dev *dev);
void pci_disable_device(struct pci_dev *dev);
/* Managed ("devm") resources: the component's life is the driver's. */
static inline int pcim_enable_device(struct pci_dev *pdev) { return pci_enable_device(pdev); }
int pci_request_regions(struct pci_dev *dev, const char *name);
static inline int pci_request_region(struct pci_dev *dev, int bar, const char *name)
{
	(void)dev; (void)bar; (void)name; /* the function is this component's alone */
	return 0;
}
void pci_release_regions(struct pci_dev *dev);
void pci_set_master(struct pci_dev *dev);
int pci_read_config_word(struct pci_dev *dev, int where, u16 *val);
int pci_write_config_word(struct pci_dev *dev, int where, u16 val);
void __iomem *pci_iomap(struct pci_dev *dev, int bar, unsigned long max);
static inline void pci_iounmap(struct pci_dev *dev, void __iomem *p) { (void)dev; (void)p; }
static inline int pci_set_mwi(struct pci_dev *dev) { (void)dev; return 0; }
static inline void pci_clear_mwi(struct pci_dev *dev) { (void)dev; }
static inline int pci_enable_wake(struct pci_dev *dev, int state, bool on) { (void)dev; (void)state; (void)on; return 0; }
static inline int pci_set_power_state(struct pci_dev *dev, int state) { (void)dev; (void)state; return 0; }
static inline void *pci_get_drvdata(struct pci_dev *dev) { return dev->dev.driver_data; }
static inline void pci_set_drvdata(struct pci_dev *dev, void *data) { dev->dev.driver_data = data; }
static inline const char *pci_name(const struct pci_dev *dev) { return dev->dev.name; }
#define pci_resource_start(dev, bar) ((dev)->resource[bar].start)
#define pci_resource_len(dev, bar) ((dev)->resource[bar].len)
#define pci_resource_flags(dev, bar) ((dev)->resource[bar].flags)

/* ---- device memory */

void __iomem *ioremap(resource_size_t phys, size_t size);
static inline void iounmap(void __iomem *p) { (void)p; }
static inline u8 readb(const void __iomem *p) { return *(const volatile u8 *)p; }
static inline u16 readw(const void __iomem *p) { return *(const volatile u16 *)p; }
static inline u32 readl(const void __iomem *p) { return *(const volatile u32 *)p; }
static inline void writeb(u8 v, void __iomem *p) { *(volatile u8 *)p = v; }
static inline void writew(u16 v, void __iomem *p) { *(volatile u16 *)p = v; }
static inline void writel(u32 v, void __iomem *p) { *(volatile u32 *)p = v; }
/* Port I/O: a port in one of the device's I/O BARs (whose start, in the
 * pci_dev, is the port the bus server gave it) is read and written by the
 * bus server for the driver, which reaches no other port; any other port
 * reads as all ones (lde.c logs it once). */
u8 inb(unsigned long port);
u16 inw(unsigned long port);
u32 inl(unsigned long port);
void outb(u8 v, unsigned long port);
void outw(u16 v, unsigned long port);
void outl(u32 v, unsigned long port);
struct resource;
static inline struct resource *request_region(unsigned long start, unsigned long n, const char *name)
{
	(void)start; (void)n; (void)name;
	return NULL;
}
static inline void release_region(unsigned long start, unsigned long n) { (void)start; (void)n; }
#define ioread8(p) readb(p)
#define ioread16(p) readw(p)
#define ioread32(p) readl(p)
#define iowrite8(v, p) writeb(v, p)
#define iowrite16(v, p) writew(v, p)
#define iowrite32(v, p) writel(v, p)
static inline void memcpy_fromio(void *dst, const void __iomem *src, size_t n)
{
	u8 *d = dst;
	const volatile u8 *s = src;
	while (n--)
		*d++ = *s++;
}

/* ---- DMA: all the environment's memory is in the device's domain */

enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE };
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL << (n)) - 1))
#define DMA_MAPPING_ERROR (~(dma_addr_t)0)
void *dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma, gfp_t gfp);
void dma_free_coherent(struct device *dev, size_t size, void *va, dma_addr_t dma);
dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size, enum dma_data_direction dir);
static inline void dma_unmap_single(struct device *dev, dma_addr_t dma, size_t size, enum dma_data_direction dir)
{
	(void)dev; (void)dma; (void)size; (void)dir;
}
static inline int dma_mapping_error(struct device *dev, dma_addr_t dma)
{
	(void)dev;
	return dma == DMA_MAPPING_ERROR;
}
/* The mask is kept: a mapping the device could not address fails. */
int dma_set_mask(struct device *dev, u64 mask);
#define dma_set_mask_and_coherent(dev, mask) dma_set_mask(dev, mask)
#define dma_rmb() barrier()
#define dma_wmb() lde_host_wmb()
static inline void dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma, size_t size, enum dma_data_direction dir)
{
	(void)dev; (void)dma; (void)size; (void)dir;
}
static inline void dma_sync_single_for_device(struct device *dev, dma_addr_t dma, size_t size, enum dma_data_direction dir)
{
	(void)dev; (void)dma; (void)size; (void)dir;
	lde_host_wmb();
}
/* A DMA pool: blocks of one size the device can reach. */
struct dma_pool;
struct dma_pool *dma_pool_create(const char *name, struct device *dev, size_t size, size_t align, size_t boundary);
void dma_pool_destroy(struct dma_pool *pool);
void *dma_pool_zalloc(struct dma_pool *pool, gfp_t gfp, dma_addr_t *dma);
void dma_pool_free(struct dma_pool *pool, void *va, dma_addr_t dma);

/* ---- interrupts */

#define IRQ_NONE 0
#define IRQ_HANDLED 1
#define IRQ_RETVAL(x) ((x) ? IRQ_HANDLED : IRQ_NONE)
#define IRQF_SHARED 0x80
typedef irqreturn_t (*irq_handler_t)(int irq, void *dev);
int request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags, const char *name, void *dev);
void free_irq(unsigned int irq, void *dev);
#define devm_request_irq(device, irq, handler, flags, name, dev) \
	((void)(device), request_irq(irq, handler, flags, name, dev))
static inline void disable_irq(unsigned int irq) { (void)irq; }
static inline void disable_irq_nosync(unsigned int irq) { (void)irq; }
static inline void enable_irq(unsigned int irq) { (void)irq; }
static inline void synchronize_irq(unsigned int irq) { (void)irq; }

/* ---- Ethernet */

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_ZLEN 60
#define ETH_DATA_LEN 1500
#define ETH_FCS_LEN 4
#define ETH_MIN_MTU 68
#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_802_3_MIN 0x0600
#define ETH_P_802_2 0x0004
#define VLAN_HLEN 4
#define VLAN_ETH_HLEN 18
#define VLAN_ETH_FRAME_LEN 1518
#define ETH_GSTRING_LEN 32
#define IFNAMSIZ 16
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct ethhdr {
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	__be16 h_proto;
} __packed;
struct iphdr {
	u8 ihl_version;
	u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	u8 ttl;
	u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};
struct sockaddr {
	unsigned short sa_family;
	char sa_data[14];
};
static inline bool is_valid_ether_addr(const u8 *a)
{
	return !(a[0] & 1) && (a[0] | a[1] | a[2] | a[3] | a[4] | a[5]);
}
u32 ether_crc(int length, unsigned char *data);

/* ---- network devices */

#define NETIF_F_SG (1ULL << 0)
#define NETIF_F_IP_CSUM (1ULL << 1)
#define NETIF_F_HW_CSUM (1ULL << 3)
#define NETIF_F_HIGHDMA (1ULL << 5)
#define NETIF_F_HW_VLAN_CTAG_TX (1ULL << 7)
#define NETIF_F_HW_VLAN_CTAG_RX (1ULL << 8)
#define NETIF_F_TSO (1ULL << 16)
#define NETIF_F_VLAN_CHALLENGED (1ULL << 10)
#define NETIF_F_RXCSUM (1ULL << 29)
#define NETIF_F_RXFCS (1ULL << 34)
#define NETIF_F_RXALL (1ULL << 35)
#define NETIF_F_CSUM_MASK (NETIF_F_IP_CSUM | NETIF_F_HW_CSUM)
#define NETIF_F_TSO_MASK NETIF_F_TSO
#define IFF_PROMISC 0x100
#define IFF_ALLMULTI 0x200
#define IFF_SUPP_NOFCS (1 << 14)
#define NETDEV_TX_OK 0
#define NETDEV_TX_BUSY 0x10
#define NETIF_MSG_DRV 0x0001
#define NETIF_MSG_PROBE 0x0002
#define NETIF_MSG_LINK 0x0004
#define netif_msg_link(p) ((p)->msg_enable & NETIF_MSG_LINK)
#define netif_err(priv, type, dev, fmt, ...) netdev_err(dev, fmt, ##__VA_ARGS__)
#define netif_info(priv, type, dev, fmt, ...) netdev_info(dev, fmt, ##__VA_ARGS__)
#define netif_warn(priv, type, dev, fmt, ...) netdev_warn(dev, fmt, ##__VA_ARGS__)
/* Used at debug level: compiled, checked and left out. */
#define netif_printk(priv, type, level, dev, fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)

struct sk_buff;
struct net_device;
struct ifreq;
struct ethtool_ops;
struct napi_struct {
	int (*poll)(struct napi_struct *napi, int budget);
	int weight;
	struct net_device *dev;
	/* lde.c: enabled; scheduled (the poll is to be called). */
	bool enabled, scheduled;
	struct napi_struct *next;
};
struct net_device_stats {
	unsigned long rx_packets, tx_packets, rx_bytes, tx_bytes;
	unsigned long rx_errors, tx_errors, rx_dropped, tx_dropped;
	unsigned long multicast, collisions;
	unsigned long rx_length_errors, rx_over_errors, rx_crc_errors;
	unsigned long rx_frame_errors, rx_fifo_errors, rx_missed_errors;
	unsigned long tx_aborted_errors, tx_carrier_errors, tx_fifo_errors;
	unsigned long tx_heartbeat_errors, tx_window_errors;
};
struct rtnl_link_stats64 {
	u64 rx_packets, tx_packets, rx_bytes, tx_bytes;
	u64 rx_errors, tx_errors, rx_dropped, tx_dropped;
	u64 multicast, collisions;
	u64 rx_length_errors, rx_over_errors, rx_crc_errors;
	u64 rx_frame_errors, rx_fifo_errors, rx_missed_errors;
	u64 tx_aborted_errors, tx_carrier_errors, tx_fifo_errors;
	u64 tx_heartbeat_errors, tx_window_errors;
};
struct net_device_ops {
	int (*ndo_open)(struct net_device *dev);
	int (*ndo_stop)(struct net_device *dev);
	netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb, struct net_device *dev);
	int (*ndo_validate_addr)(struct net_device *dev);
	int (*ndo_set_mac_address)(struct net_device *dev, void *addr);
	void (*ndo_set_rx_mode)(struct net_device *dev);
	struct net_device_stats *(*ndo_get_stats)(struct net_device *dev);
	void (*ndo_get_stats64)(struct net_device *dev, struct rtnl_link_stats64 *stats);
	int (*ndo_eth_ioctl)(struct net_device *dev, struct ifreq *ifr, int cmd);
	void (*ndo_tx_timeout)(struct net_device *dev, unsigned int txqueue);
	int (*ndo_set_features)(struct net_device *dev, netdev_features_t features);
	int (*ndo_change_mtu)(struct net_device *dev, int new_mtu);
	netdev_features_t (*ndo_features_check)(struct sk_buff *skb, struct net_device *dev,
						netdev_features_t features);
	void (*ndo_poll_controller)(struct net_device *dev);
};
struct net_device {
	char name[IFNAMSIZ];
	const unsigned char *dev_addr;
	unsigned char lde_addr[8];
	unsigned int flags, priv_flags;
	unsigned int mtu, min_mtu, max_mtu;
	netdev_features_t features, hw_features, vlan_features;
	const struct net_device_ops *netdev_ops;
	const struct ethtool_ops *ethtool_ops;
	int watchdog_timeo;
	struct net_device_stats stats;
	struct device dev;
	/* lde.c's: the interface is up; the driver stopped the transmit
	 * queue (and since when); the link has a carrier; the driver has
	 * not detached the device. */
	bool lde_running, lde_stopped, lde_carrier, lde_present;
	unsigned long lde_stopped_at;
	void *lde_priv;
};
struct netdev_hw_addr {
	unsigned char addr[32];
};

struct net_device *alloc_etherdev(int sizeof_priv);
void free_netdev(struct net_device *dev);
int register_netdev(struct net_device *dev);
void unregister_netdev(struct net_device *dev);
int eth_validate_addr(struct net_device *dev);
void eth_hw_addr_set(struct net_device *dev, const u8 *addr);
__be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev);
void netif_carrier_on(struct net_device *dev);
void netif_carrier_off(struct net_device *dev);
void netif_stop_queue(struct net_device *dev);
void netif_wake_queue(struct net_device *dev);
static inline void *netdev_priv(const struct net_device *dev) { return dev->lde_priv; }
#define SET_NETDEV_DEV(net, pdev) ((net)->dev.parent = (pdev))
static inline void netif_start_queue(struct net_device *dev) { dev->lde_stopped = false; }
static inline bool netif_queue_stopped(const struct net_device *dev) { return dev->lde_stopped; }
static inline bool netif_running(const struct net_device *dev) { return dev->lde_running; }
static inline bool netif_carrier_ok(const struct net_device *dev) { return dev->lde_carrier; }
static inline bool netif_device_present(const struct net_device *dev) { return dev->lde_present; }
static inline void netif_device_detach(struct net_device *dev) { dev->lde_present = false; }
static inline void netif_device_attach(struct net_device *dev) { dev->lde_present = true; }
static inline void netdev_sent_queue(struct net_device *dev, unsigned int bytes) { (void)dev; (void)bytes; }
static inline void netdev_completed_queue(struct net_device *dev, unsigned int pkts, unsigned int bytes)
{
	(void)dev; (void)pkts; (void)bytes;
}
static inline void netdev_reset_queue(struct net_device *dev) { (void)dev; }
/* No multicast addresses are ever subscribed. */
#define netdev_mc_count(dev) ((void)(dev), 0)
#define netdev_for_each_mc_addr(ha, dev) for ((void)(dev), (ha) = NULL; (ha); (ha) = NULL)
static inline void netdev_stats_to_stats64(struct rtnl_link_stats64 *s64, const struct net_device_stats *s)
{
	const unsigned long *from = (const unsigned long *)s;
	u64 *to = (u64 *)s64;
	for (unsigned i = 0; i < sizeof(*s) / sizeof(unsigned long); i++)
		to[i] = from[i];
}
#define netdev_err(dev, fmt, ...) _printk("%s: " fmt, (dev)->name, ##__VA_ARGS__)
#define netdev_warn(dev, fmt, ...) _printk("%s: " fmt, (dev)->name, ##__VA_ARGS__)
#define netdev_info(dev, fmt, ...) _printk("%s: " fmt, (dev)->name, ##__VA_ARGS__)
#define netdev_dbg(dev, fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)
#define netif_dbg(priv, type, dev, fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)
#define netdev_WARN_ONCE(dev, fmt, ...) lde_once(netdev_warn(dev, fmt, ##__VA_ARGS__))

/* u64 statistics: one thread, so they are always consistent. */
struct u64_stats_sync { int unused; };
#define u64_stats_init(s) ((void)(s))
#define u64_stats_update_begin(s) ((void)(s))
#define u64_stats_update_end(s) ((void)(s))
#define u64_stats_fetch_begin(s) ((void)(s), 0u)
#define u64_stats_fetch_retry(s, start) ((void)(s), (void)(start), 0)

/* ---- NAPI: the host calls the poll after the interrupt handler */

void netif_napi_add_weight(struct net_device *dev, struct napi_struct *napi,
			   int (*poll)(struct napi_struct *, int), int weight);
#define netif_napi_add(dev, napi, poll) netif_napi_add_weight(dev, napi, poll, 64)
void napi_enable(struct napi_struct *napi);
void napi_disable(struct napi_struct *napi);
bool napi_schedule_prep(struct napi_struct *napi);
bool napi_complete_done(struct napi_struct *napi, int work_done);
static inline void __napi_schedule(struct napi_struct *napi) { (void)napi; }
static inline void napi_schedule_irqoff(struct napi_struct *napi) { napi_schedule_prep(napi); }
static inline void napi_schedule(struct napi_struct *napi) { napi_schedule_prep(napi); }

/* ---- socket buffers: one linear buffer each, never fragments */

#define MAX_SKB_FRAGS 17
#define CHECKSUM_NONE 0
#define CHECKSUM_UNNECESSARY 1
#define CHECKSUM_PARTIAL 3
typedef struct {
	void *lde_address;
	unsigned int lde_size;
} skb_frag_t;
struct skb_shared_info {
	u8 nr_frags;
	u16 gso_size;
	skb_frag_t frags[1];
};
struct sk_buff {
	unsigned char *head, *data;
	unsigned int len, data_len;
	/* Bytes at `head`. */
	unsigned int lde_size;
	__be16 protocol;
	u16 vlan_tci;
	u8 ip_summed;
	bool lde_vlan, no_fcs;
	struct net_device *dev;
	unsigned char *lde_mac_header;
	struct skb_shared_info lde_shared;
};
struct sk_buff *alloc_skb(unsigned int size, gfp_t gfp);
struct sk_buff *netdev_alloc_skb_ip_align(struct net_device *dev, unsigned int length);
#define netdev_alloc_skb(dev, length) netdev_alloc_skb_ip_align(dev, length)
static inline void skb_tx_timestamp(struct sk_buff *skb) { (void)skb; }
struct sk_buff *napi_alloc_skb(struct napi_struct *napi, unsigned int length);
void kfree_skb(struct sk_buff *skb);
#define dev_kfree_skb(skb) kfree_skb(skb)
#define dev_kfree_skb_any(skb) kfree_skb(skb)
#define dev_kfree_skb_irq(skb) kfree_skb(skb)
#define dev_consume_skb_irq(skb) kfree_skb(skb)
#define dev_consume_skb_any(skb) kfree_skb(skb)
void *skb_put(struct sk_buff *skb, unsigned int len);
int netif_receive_skb(struct sk_buff *skb);
#define napi_gro_receive(napi, skb) netif_receive_skb(skb)
#define netif_rx(skb) netif_receive_skb(skb)
static inline struct skb_shared_info *skb_shinfo(struct sk_buff *skb) { return &skb->lde_shared; }
static inline unsigned int skb_headlen(const struct sk_buff *skb) { return skb->len - skb->data_len; }
static inline unsigned int skb_frag_size(const skb_frag_t *f) { return f->lde_size; }
static inline void *skb_frag_address(const skb_frag_t *f) { return f->lde_address; }
static inline void skb_reserve(struct sk_buff *skb, int len) { skb->data += len; }
static inline bool skb_vlan_tag_present(const struct sk_buff *skb) { return skb->lde_vlan; }
static inline u16 skb_vlan_tag_get(const struct sk_buff *skb) { return skb->vlan_tci; }
static inline void __vlan_hwaccel_put_tag(struct sk_buff *skb, __be16 proto, u16 tci)
{
	(void)proto;
	skb->vlan_tci = tci;
	skb->lde_vlan = true;
}
static inline void skb_checksum_none_assert(const struct sk_buff *skb) { (void)skb; }
static inline struct iphdr *ip_hdr(const struct sk_buff *skb) { return (struct iphdr *)(skb->data + ETH_HLEN); }
static inline netdev_features_t vlan_features_check(struct sk_buff *skb, netdev_features_t features)
{
	(void)skb;
	return features;
}
static inline void skb_copy_to_linear_data(struct sk_buff *skb, const void *from, unsigned int len)
{
	memcpy(skb->data, from, len);
}
static inline void skb_copy_to_linear_data_offset(struct sk_buff *skb, int off, const void *from, unsigned int len)
{
	memcpy(skb->data + off, from, len);
}

/* ---- MII (lde.c) */

/* The MII management registers and their bits (IEEE 802.3, clause 22). */
#define MII_BMCR 0x00
#define MII_BMSR 0x01
#define MII_PHYSID1 0x02
#define MII_PHYSID2 0x03
#define MII_ADVERTISE 0x04
#define MII_LPA 0x05
#define MII_EXPANSION 0x06
#define MII_CTRL1000 0x09
#define MII_STAT1000 0x0a
#define MII_ESTATUS 0x0f
#define MII_DCOUNTER 0x12
#define MII_FCSCOUNTER 0x13
#define MII_NWAYTEST 0x14
#define MII_RERRCOUNTER 0x15
#define MII_SREVISION 0x16
#define MII_RESV1 0x17
#define MII_LBRERROR 0x18
#define MII_PHYADDR 0x19
#define MII_RESV2 0x1a
#define MII_TPISTATUS 0x1b
#define MII_NCONFIG 0x1c
#define BMCR_SPEED1000 0x0040
#define BMCR_CTST 0x0080
#define BMCR_FULLDPLX 0x0100
#define BMCR_ANRESTART 0x0200
#define BMCR_ISOLATE 0x0400
#define BMCR_PDOWN 0x0800
#define BMCR_ANENABLE 0x1000
#define BMCR_SPEED100 0x2000
#define BMCR_LOOPBACK 0x4000
#define BMCR_RESET 0x8000
#define BMSR_ERCAP 0x0001
#define BMSR_JCD 0x0002
#define BMSR_LSTATUS 0x0004
#define BMSR_ANEGCAPABLE 0x0008
#define BMSR_RFAULT 0x0010
#define BMSR_ANEGCOMPLETE 0x0020
#define BMSR_10HALF 0x0800
#define BMSR_10FULL 0x1000
#define BMSR_100HALF 0x2000
#define BMSR_100FULL 0x4000
#define BMSR_100BASE4 0x8000
#define ADVERTISE_CSMA 0x0001
#define ADVERTISE_10HALF 0x0020
#define ADVERTISE_10FULL 0x0040
#define ADVERTISE_100HALF 0x0080
#define ADVERTISE_100FULL 0x0100
#define ADVERTISE_100BASE4 0x0200
#define ADVERTISE_PAUSE_CAP 0x0400
#define ADVERTISE_PAUSE_ASYM 0x0800
#define ADVERTISE_ALL (ADVERTISE_10HALF | ADVERTISE_10FULL | ADVERTISE_100HALF | ADVERTISE_100FULL)
#define LPA_10HALF 0x0020
#define LPA_10FULL 0x0040
#define LPA_100HALF 0x0080
#define LPA_100FULL 0x0100
#define LPA_100BASE4 0x0200
#define LPA_LPACK 0x4000
#define EXPANSION_NWAY 0x0001
struct mii_if_info {
	int phy_id;
	int advertising;
	int phy_id_mask;
	int reg_num_mask;
	unsigned int full_duplex : 1;
	unsigned int force_media : 1;
	unsigned int supports_gmii : 1;
	struct net_device *dev;
	int (*mdio_read)(struct net_device *dev, int phy_id, int location);
	void (*mdio_write)(struct net_device *dev, int phy_id, int location, int val);
};
struct mii_ioctl_data {
	u16 phy_id, reg_num, val_in, val_out;
};
struct ifreq {
	char ifr_name[IFNAMSIZ];
	struct mii_ioctl_data lde_mii;
};
static inline struct mii_ioctl_data *if_mii(struct ifreq *rq) { return &rq->lde_mii; }
struct ethtool_link_ksettings;
unsigned int mii_check_media(struct mii_if_info *mii, unsigned int ok_to_print, unsigned int init_media);
int mii_link_ok(struct mii_if_info *mii);
int mii_nway_restart(struct mii_if_info *mii);
#define ETHTOOL_GSET 1
#define SPEED_10 10
#define SPEED_100 100
#define DUPLEX_HALF 0
#define DUPLEX_FULL 1
#define AUTONEG_DISABLE 0
#define AUTONEG_ENABLE 1
struct ethtool_cmd {
	u32 cmd, supported, advertising;
	u16 speed;
	u8 duplex, port, phy_address, transceiver, autoneg;
	u16 speed_hi;
};
static inline u32 ethtool_cmd_speed(const struct ethtool_cmd *c) { return (u32)c->speed_hi << 16 | c->speed; }
void mii_ethtool_gset(struct mii_if_info *mii, struct ethtool_cmd *cmd);
int mii_ethtool_sset(struct mii_if_info *mii, struct ethtool_cmd *cmd);
void mii_check_link(struct mii_if_info *mii);
void mii_ethtool_get_link_ksettings(struct mii_if_info *mii, struct ethtool_link_ksettings *cmd);
int mii_ethtool_set_link_ksettings(struct mii_if_info *mii, const struct ethtool_link_ksettings *cmd);
int generic_mii_ioctl(struct mii_if_info *mii, struct mii_ioctl_data *data, int cmd, unsigned int *duplex_changed);

/* ---- ethtool: the tables compile; nothing calls them yet */

#define ETH_SS_TEST 0
#define ETH_SS_STATS 1
#define ETH_TEST_FL_OFFLINE 1
#define ETH_TEST_FL_FAILED 2
struct ethtool_test {
	u32 cmd, flags, reserved, len;
};
struct ethtool_ts_info;
enum ethtool_phys_id_state { ETHTOOL_ID_INACTIVE, ETHTOOL_ID_ACTIVE, ETHTOOL_ID_ON, ETHTOOL_ID_OFF };
#define WAKE_PHY (1 << 0)
#define WAKE_UCAST (1 << 1)
#define WAKE_MCAST (1 << 2)
#define WAKE_BCAST (1 << 3)
#define WAKE_ARP (1 << 4)
#define WAKE_MAGIC (1 << 5)
struct ethtool_drvinfo {
	char driver[32], version[32], fw_version[32], bus_info[32];
};
struct ethtool_regs {
	u32 cmd, version, len;
};
struct ethtool_wolinfo {
	u32 cmd, supported, wolopts;
};
struct ethtool_stats {
	u32 cmd, n_stats;
};
struct ethtool_eeprom {
	u32 cmd, magic, offset, len;
};
struct ethtool_ringparam {
	u32 cmd, rx_max_pending, rx_mini_max_pending, rx_jumbo_max_pending, tx_max_pending;
	u32 rx_pending, rx_mini_pending, rx_jumbo_pending, tx_pending;
};
struct kernel_ethtool_ringparam {
	u32 rx_buf_len;
};
struct netlink_ext_ack;
struct ethtool_ops {
	void (*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
	int (*get_regs_len)(struct net_device *);
	void (*get_regs)(struct net_device *, struct ethtool_regs *, void *);
	void (*get_wol)(struct net_device *, struct ethtool_wolinfo *);
	int (*set_wol)(struct net_device *, struct ethtool_wolinfo *);
	u32 (*get_msglevel)(struct net_device *);
	void (*set_msglevel)(struct net_device *, u32);
	int (*nway_reset)(struct net_device *);
	u32 (*get_link)(struct net_device *);
	int (*get_eeprom_len)(struct net_device *);
	int (*get_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*set_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	void (*get_ringparam)(struct net_device *, struct ethtool_ringparam *,
			      struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	int (*set_ringparam)(struct net_device *, struct ethtool_ringparam *,
			     struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	void (*self_test)(struct net_device *, struct ethtool_test *, u64 *);
	int (*set_phys_id)(struct net_device *, enum ethtool_phys_id_state);
	int (*get_ts_info)(struct net_device *, struct ethtool_ts_info *);
	void (*get_strings)(struct net_device *, u32 stringset, u8 *);
	void (*get_ethtool_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int (*get_sset_count)(struct net_device *, int);
	int (*get_link_ksettings)(struct net_device *, struct ethtool_link_ksettings *);
	int (*set_link_ksettings)(struct net_device *, const struct ethtool_link_ksettings *);
};
u32 ethtool_op_get_link(struct net_device *dev);
int ethtool_op_get_ts_info(struct net_device *dev, struct ethtool_ts_info *info);

#endif
