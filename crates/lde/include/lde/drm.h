/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * The Linux Driver Environment's DRM: the part of Linux's display API
 * (KMS) a hosted display driver uses, written for Superior. As with
 * lde/linux.h, the names and meanings are Linux's, so a driver compiles
 * unchanged; the implementation is lde-drm.c's.
 *
 * Every <drm/...> header a driver includes is this file. There is one
 * device with one display pipeline: a primary plane, a CRTC, an encoder
 * and a connector, as drm_simple_kms_helper builds them. Framebuffers are
 * buffer objects in the card's video memory (drm_gem_vram_helper's), and
 * an atomic commit runs the driver's own check, enable, update and
 * disable hooks in Linux's order. Userspace is the Rust host: it picks a
 * mode from those the connector reports, and flips between two buffers.
 */
#ifndef LDE_DRM_H
#define LDE_DRM_H

#include <lde/linux.h>

/* ---- printing */

#define DRM_INFO(fmt, ...) _printk("[drm] " fmt, ##__VA_ARGS__)
#define DRM_WARN(fmt, ...) _printk("[drm] *WARNING* " fmt, ##__VA_ARGS__)
#define DRM_ERROR(fmt, ...) _printk("[drm:%s] *ERROR* " fmt, __func__, ##__VA_ARGS__)
#define DRM_DEBUG(fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)
#define DRM_DEBUG_DRIVER(fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)
#define DRM_DEBUG_KMS(fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)
#define drm_info(drm, fmt, ...) DRM_INFO(fmt, ##__VA_ARGS__)
#define drm_err(drm, fmt, ...) DRM_ERROR(fmt, ##__VA_ARGS__)
#define drm_warn(drm, fmt, ...) DRM_WARN(fmt, ##__VA_ARGS__)
#define drm_dbg(drm, fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)
#define drm_dbg_kms(drm, fmt, ...) lde_no_print(fmt, ##__VA_ARGS__)

/* ---- pixel formats */

#define fourcc_code(a, b, c, d) \
	((u32)(a) | ((u32)(b) << 8) | ((u32)(c) << 16) | ((u32)(d) << 24))
#define DRM_FORMAT_C8 fourcc_code('C', '8', ' ', ' ')
#define DRM_FORMAT_RGB565 fourcc_code('R', 'G', '1', '6')
#define DRM_FORMAT_RGB888 fourcc_code('R', 'G', '2', '4')
#define DRM_FORMAT_XRGB8888 fourcc_code('X', 'R', '2', '4')
#define DRM_FORMAT_BGRX8888 fourcc_code('B', 'X', '2', '4')
#define DRM_FORMAT_MOD_LINEAR 0ull
#define DRM_FORMAT_MOD_INVALID 0x00ffffffffffffffull

struct drm_format_info {
	u32 format;
	u8 depth;
	u8 num_planes;
	u8 cpp[4];
};
/* The formats lde-drm.c knows; NULL for others. */
const struct drm_format_info *drm_format_info(u32 format);
unsigned int drm_format_info_min_pitch(const struct drm_format_info *info, int plane, unsigned int width);

/* ---- modes */

#define DRM_DISPLAY_MODE_LEN 32
#define DRM_MODE_TYPE_PREFERRED (1 << 3)
#define DRM_MODE_TYPE_DRIVER (1 << 6)
#define DRM_MODE_FLAG_PHSYNC (1 << 0)
#define DRM_MODE_FLAG_NHSYNC (1 << 1)
#define DRM_MODE_FLAG_PVSYNC (1 << 2)
#define DRM_MODE_FLAG_NVSYNC (1 << 3)

struct drm_display_mode {
	int clock; /* kHz */
	u16 hdisplay, hsync_start, hsync_end, htotal, hskew;
	u16 vdisplay, vsync_start, vsync_end, vtotal, vscan;
	u32 flags;
	u32 type;
	char name[DRM_DISPLAY_MODE_LEN];
};
/* The refresh rate in Hz, rounded. */
int drm_mode_vrefresh(const struct drm_display_mode *mode);

enum drm_mode_status {
	MODE_OK = 0,
	MODE_HSYNC,
	MODE_VSYNC,
	MODE_H_ILLEGAL,
	MODE_V_ILLEGAL,
	MODE_BAD_WIDTH,
	MODE_NOMODE,
	MODE_NO_INTERLACE,
	MODE_NO_DBLESCAN,
	MODE_NO_VSCAN,
	MODE_MEM,
	MODE_VIRTUAL_X,
	MODE_VIRTUAL_Y,
	MODE_MEM_VIRT,
	MODE_NOCLOCK,
	MODE_CLOCK_HIGH,
	MODE_CLOCK_LOW,
	MODE_BAD = -2,
	MODE_ERROR = -1,
};

/* ---- the device */

struct drm_device;
struct drm_file;
struct drm_framebuffer;
struct drm_atomic_state;
struct drm_simple_display_pipe;
struct drm_connector;

struct drm_mode_fb_cmd2 {
	u32 fb_id, width, height, pixel_format, flags;
	u32 handles[4], pitches[4], offsets[4];
	u64 modifier[4];
};

struct drm_mode_config_funcs {
	struct drm_framebuffer *(*fb_create)(struct drm_device *dev, struct drm_file *file,
					     const struct drm_mode_fb_cmd2 *cmd);
	enum drm_mode_status (*mode_valid)(struct drm_device *dev, const struct drm_display_mode *mode);
	int (*atomic_check)(struct drm_device *dev, struct drm_atomic_state *state);
	int (*atomic_commit)(struct drm_device *dev, struct drm_atomic_state *state, bool nonblock);
};

struct drm_mode_config {
	int min_width, min_height, max_width, max_height;
	u32 preferred_depth, prefer_shadow;
	bool quirk_addfb_prefer_host_byte_order;
	const struct drm_mode_config_funcs *funcs;
};

/* Video memory, as drm_gem_vram_helper manages it: pages handed out
 * first-fit, each buffer object pinned while it is scanned out. */
struct lde_vram {
	u64 base, size;
	u8 __iomem *map;
	u8 *used; /* a byte per page */
};

#define DRIVER_GEM BIT(0)
#define DRIVER_MODESET BIT(1)
#define DRIVER_RENDER BIT(3)
#define DRIVER_ATOMIC BIT(4)

struct file_operations {
	int lde_unused;
};
#define DEFINE_DRM_GEM_FOPS(name) static const struct file_operations name = { 0 }

struct drm_driver {
	u32 driver_features;
	const struct file_operations *fops;
	const char *name, *desc, *date;
	int major, minor, patchlevel;
	/* Buffers live in video memory (DRM_GEM_VRAM_DRIVER). */
	bool lde_vram;
};
#define DRM_GEM_VRAM_DRIVER .lde_vram = true

struct drm_device {
	struct device *dev;
	void *dev_private;
	const struct drm_driver *driver;
	struct drm_mode_config mode_config;
	bool registered, unplugged;
	struct lde_vram *vram_mm;
	struct drm_simple_display_pipe *lde_pipe;
	struct drm_connector *lde_connector;
};

struct drm_device *drm_dev_alloc(const struct drm_driver *driver, struct device *parent);
int drm_dev_register(struct drm_device *dev, unsigned long flags);
void drm_dev_put(struct drm_device *dev);
void drm_dev_unplug(struct drm_device *dev);
bool drm_dev_enter(struct drm_device *dev, int *idx);
void drm_dev_exit(int idx);
void *drmm_kzalloc(struct drm_device *dev, size_t size, gfp_t gfp);
int drmm_mode_config_init(struct drm_device *dev);
void drm_mode_config_reset(struct drm_device *dev);
/* Firmware framebuffers: there are none to take over. */
static inline int drm_aperture_remove_conflicting_pci_framebuffers(struct pci_dev *pdev,
								  const struct drm_driver *drv)
{
	(void)pdev; (void)drv;
	return 0;
}
/* The fbdev console: there is no console on the display. */
static inline void drm_fbdev_generic_setup(struct drm_device *dev, unsigned int bpp)
{
	(void)dev; (void)bpp;
}
static inline int pcim_enable_device(struct pci_dev *pdev) { return pci_enable_device(pdev); }
#define devm_ioremap(dev, phys, size) ((void)(dev), ioremap(phys, size))

#define drm_module_pci_driver_if_modeset(drv, modeset) \
	int lde_module_init(void) { return (modeset) == 0 ? -ENODEV : pci_register_driver(&drv); } \
	void lde_module_exit(void) { pci_unregister_driver(&drv); }
#define drm_module_pci_driver(drv) drm_module_pci_driver_if_modeset(drv, -1)

/* ---- buffer objects and framebuffers */

struct drm_gem_object {
	struct drm_device *dev;
	size_t size;
};
struct lde_ttm_bo {
	struct drm_gem_object base;
};
struct drm_gem_vram_object {
	struct lde_ttm_bo bo;
	u64 offset;  /* in video memory */
	int pin_count;
};
#define drm_gem_vram_of_gem(obj) container_of(obj, struct drm_gem_vram_object, bo.base)
/* Where in video memory the object is, while pinned; -ENODEV if not. */
s64 drm_gem_vram_offset(struct drm_gem_vram_object *gbo);
int drmm_vram_helper_init(struct drm_device *dev, u64 vram_base, size_t vram_size);
enum drm_mode_status drm_vram_helper_mode_valid(struct drm_device *dev, const struct drm_display_mode *mode);

struct drm_framebuffer {
	struct drm_device *dev;
	const struct drm_format_info *format;
	unsigned int pitches[4], offsets[4];
	u64 modifier;
	unsigned int width, height;
	int flags;
	struct drm_gem_object *obj[4];
};
struct drm_framebuffer *drm_gem_fb_create(struct drm_device *dev, struct drm_file *file,
					  const struct drm_mode_fb_cmd2 *cmd);

/* ---- the pipeline's state */

struct drm_crtc;
struct drm_plane;

struct drm_plane_state {
	struct drm_plane *plane;
	struct drm_crtc *crtc;
	struct drm_framebuffer *fb;
	int crtc_x, crtc_y;
	unsigned int crtc_w, crtc_h;
	u32 src_x, src_y, src_w, src_h;
	bool visible;
	struct drm_atomic_state *state;
};
struct drm_crtc_state {
	struct drm_crtc *crtc;
	bool enable, active, mode_changed;
	struct drm_display_mode mode;
	struct drm_atomic_state *state;
};
struct drm_connector_state {
	struct drm_connector *connector;
	struct drm_crtc *crtc;
};

struct drm_plane {
	struct drm_device *dev;
	struct drm_plane_state *state;
	const u32 *format_types;
	unsigned int format_count;
};
struct drm_crtc {
	struct drm_device *dev;
	struct drm_crtc_state *state;
	struct drm_plane *primary;
};
struct drm_encoder {
	struct drm_device *dev;
	u32 possible_crtcs;
};

/* One commit: the plane's and CRTC's states before and after. */
struct drm_atomic_state {
	struct drm_device *dev;
	struct drm_plane *plane;
	struct drm_crtc *crtc;
	struct drm_plane_state *old_plane_state, *new_plane_state;
	struct drm_crtc_state *old_crtc_state, *new_crtc_state;
};
int drm_atomic_helper_check(struct drm_device *dev, struct drm_atomic_state *state);
int drm_atomic_helper_commit(struct drm_device *dev, struct drm_atomic_state *state, bool nonblock);
void drm_atomic_helper_shutdown(struct drm_device *dev);

/* ---- the connector and its modes */

#define DRM_MODE_CONNECTOR_VGA 1
#define DRM_MODE_CONNECTOR_VIRTUAL 15

struct drm_connector_funcs {
	int (*fill_modes)(struct drm_connector *connector, u32 max_width, u32 max_height);
	void (*destroy)(struct drm_connector *connector);
	void (*reset)(struct drm_connector *connector);
	struct drm_connector_state *(*atomic_duplicate_state)(struct drm_connector *connector);
	void (*atomic_destroy_state)(struct drm_connector *connector, struct drm_connector_state *state);
};
struct drm_connector_helper_funcs {
	int (*get_modes)(struct drm_connector *connector);
};

/* The connector's modes: a fixed list, filled by fill_modes. */
#define LDE_MAX_MODES 32
struct drm_connector {
	struct drm_device *dev;
	const struct drm_connector_funcs *funcs;
	const struct drm_connector_helper_funcs *helper_private;
	int connector_type;
	struct drm_connector_state *state;
	const struct edid *lde_edid;
	/* Modes get_modes added, and those fill_modes kept. */
	struct drm_display_mode lde_probed[LDE_MAX_MODES];
	int lde_probed_count;
	struct drm_display_mode lde_modes[LDE_MAX_MODES];
	int lde_mode_count;
};

int drm_connector_init(struct drm_device *dev, struct drm_connector *connector,
		       const struct drm_connector_funcs *funcs, int connector_type);
static inline void drm_connector_helper_add(struct drm_connector *connector,
					    const struct drm_connector_helper_funcs *funcs)
{
	connector->helper_private = funcs;
}
void drm_connector_cleanup(struct drm_connector *connector);
void drm_atomic_helper_connector_reset(struct drm_connector *connector);
struct drm_connector_state *drm_atomic_helper_connector_duplicate_state(struct drm_connector *connector);
void drm_atomic_helper_connector_destroy_state(struct drm_connector *connector, struct drm_connector_state *state);
int drm_helper_probe_single_connector_modes(struct drm_connector *connector, u32 max_width, u32 max_height);
/* VESA's standard modes up to a size, for a connector with no EDID. */
int drm_add_modes_noedid(struct drm_connector *connector, int hdisplay, int vdisplay);
void drm_set_preferred_mode(struct drm_connector *connector, int hpref, int vpref);

/* ---- EDID */

#define EDID_LENGTH 128
struct edid {
	u8 raw[EDID_LENGTH];
};
/* How many of the eight header bytes are right. */
int drm_edid_header_is_valid(const void *edid);
struct edid *drm_do_get_edid(struct drm_connector *connector,
			     int (*get_edid_block)(void *data, u8 *buf, unsigned int block, size_t len),
			     void *data);
/* The modes an EDID describes: its detailed timings (the first is the
 * preferred mode), established and standard timings. */
int drm_add_edid_modes(struct drm_connector *connector, struct edid *edid);
static inline int drm_connector_attach_edid_property(struct drm_connector *connector)
{
	(void)connector;
	return 0;
}
int drm_connector_update_edid_property(struct drm_connector *connector, const struct edid *edid);

/* ---- the simple display pipeline */

struct drm_simple_display_pipe_funcs {
	enum drm_mode_status (*mode_valid)(struct drm_simple_display_pipe *pipe,
					   const struct drm_display_mode *mode);
	void (*enable)(struct drm_simple_display_pipe *pipe, struct drm_crtc_state *crtc_state,
		       struct drm_plane_state *plane_state);
	void (*disable)(struct drm_simple_display_pipe *pipe);
	int (*check)(struct drm_simple_display_pipe *pipe, struct drm_plane_state *plane_state,
		     struct drm_crtc_state *crtc_state);
	void (*update)(struct drm_simple_display_pipe *pipe, struct drm_plane_state *old_plane_state);
	int (*prepare_fb)(struct drm_simple_display_pipe *pipe, struct drm_plane_state *plane_state);
	void (*cleanup_fb)(struct drm_simple_display_pipe *pipe, struct drm_plane_state *plane_state);
};
struct drm_simple_display_pipe {
	struct drm_crtc crtc;
	struct drm_plane plane;
	struct drm_encoder encoder;
	struct drm_connector *connector;
	const struct drm_simple_display_pipe_funcs *funcs;
};
int drm_simple_display_pipe_init(struct drm_device *dev, struct drm_simple_display_pipe *pipe,
				 const struct drm_simple_display_pipe_funcs *funcs, const u32 *formats,
				 unsigned int format_count, const u64 *format_modifiers,
				 struct drm_connector *connector);
int drm_gem_vram_simple_display_pipe_prepare_fb(struct drm_simple_display_pipe *pipe,
						struct drm_plane_state *new_state);
void drm_gem_vram_simple_display_pipe_cleanup_fb(struct drm_simple_display_pipe *pipe,
						 struct drm_plane_state *old_state);

#endif
