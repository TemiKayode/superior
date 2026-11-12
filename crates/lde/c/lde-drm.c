// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * The Linux Driver Environment's DRM: the display API a hosted display
 * driver calls (lde/drm.h), for one device with one pipeline, and what
 * the Rust host calls to drive it (lde/host.h). Written for Superior;
 * nothing here is Linux's, but it follows Linux's helpers in what it
 * calls when: the connector's modes come from the driver's get_modes and
 * are filtered by its mode_valid; a commit is checked by the driver's
 * atomic_check, then runs its disable, prepare_fb, update, enable and
 * cleanup_fb hooks in the order Linux's commit tail does.
 */
#include <lde/host.h>
#include <lde/drm.h>

/* ---- formats */

static const struct drm_format_info formats[] = {
	{ .format = DRM_FORMAT_C8, .depth = 8, .num_planes = 1, .cpp = { 1 } },
	{ .format = DRM_FORMAT_RGB565, .depth = 16, .num_planes = 1, .cpp = { 2 } },
	{ .format = DRM_FORMAT_RGB888, .depth = 24, .num_planes = 1, .cpp = { 3 } },
	{ .format = DRM_FORMAT_XRGB8888, .depth = 24, .num_planes = 1, .cpp = { 4 } },
	{ .format = DRM_FORMAT_BGRX8888, .depth = 24, .num_planes = 1, .cpp = { 4 } },
};

const struct drm_format_info *drm_format_info(u32 format)
{
	for (unsigned int i = 0; i < ARRAY_SIZE(formats); i++)
		if (formats[i].format == format)
			return &formats[i];
	return NULL;
}

unsigned int drm_format_info_min_pitch(const struct drm_format_info *info, int plane, unsigned int width)
{
	return info ? width * info->cpp[plane] : 0;
}

/* ---- modes */

int drm_mode_vrefresh(const struct drm_display_mode *mode)
{
	u64 pixels = (u64)mode->htotal * mode->vtotal;
	return pixels ? (int)(((u64)mode->clock * 1000 + pixels / 2) / pixels) : 0;
}

#define NH DRM_MODE_FLAG_NHSYNC
#define PH DRM_MODE_FLAG_PHSYNC
#define NV DRM_MODE_FLAG_NVSYNC
#define PV DRM_MODE_FLAG_PVSYNC
#define DMT(c, hd, hss, hse, ht, vd, vss, vse, vt, f) \
	{ .clock = c, .hdisplay = hd, .hsync_start = hss, .hsync_end = hse, .htotal = ht, \
	  .vdisplay = vd, .vsync_start = vss, .vsync_end = vse, .vtotal = vt, .flags = f }

/* VESA's Display Monitor Timings, the progressive ones up to 1920x1200. */
static const struct drm_display_mode dmt[] = {
	DMT(25175, 640, 656, 752, 800, 480, 490, 492, 525, NH | NV),
	DMT(31500, 640, 664, 704, 832, 480, 489, 492, 520, NH | NV),
	DMT(31500, 640, 656, 720, 840, 480, 481, 484, 500, NH | NV),
	DMT(36000, 800, 824, 896, 1024, 600, 601, 603, 625, PH | PV),
	DMT(40000, 800, 840, 968, 1056, 600, 601, 605, 628, PH | PV),
	DMT(50000, 800, 856, 976, 1040, 600, 637, 643, 666, PH | PV),
	DMT(49500, 800, 816, 896, 1056, 600, 601, 604, 625, PH | PV),
	DMT(65000, 1024, 1048, 1184, 1344, 768, 771, 777, 806, NH | NV),
	DMT(75000, 1024, 1048, 1184, 1328, 768, 771, 777, 806, NH | NV),
	DMT(78750, 1024, 1040, 1136, 1312, 768, 769, 772, 800, PH | PV),
	DMT(108000, 1152, 1216, 1344, 1600, 864, 865, 868, 900, PH | PV),
	DMT(79500, 1280, 1344, 1472, 1664, 768, 771, 778, 798, NH | PV),
	DMT(83500, 1280, 1352, 1480, 1680, 800, 803, 809, 831, NH | PV),
	DMT(108000, 1280, 1376, 1488, 1800, 960, 961, 964, 1000, PH | PV),
	DMT(108000, 1280, 1328, 1440, 1688, 1024, 1025, 1028, 1066, PH | PV),
	DMT(135000, 1280, 1296, 1440, 1688, 1024, 1025, 1028, 1066, PH | PV),
	DMT(85500, 1360, 1424, 1536, 1792, 768, 771, 777, 795, PH | PV),
	DMT(121750, 1400, 1488, 1632, 1864, 1050, 1053, 1057, 1089, NH | PV),
	DMT(106500, 1440, 1520, 1672, 1904, 900, 903, 909, 934, NH | PV),
	DMT(162000, 1600, 1664, 1856, 2160, 1200, 1201, 1204, 1250, PH | PV),
	DMT(146250, 1680, 1784, 1960, 2240, 1050, 1053, 1059, 1089, NH | PV),
	DMT(148500, 1920, 2008, 2052, 2200, 1080, 1084, 1089, 1125, PH | PV),
	DMT(193250, 1920, 2056, 2256, 2592, 1200, 1203, 1209, 1245, NH | PV),
};

static void name_mode(struct drm_display_mode *m)
{
	/* "WIDTHxHEIGHT", as Linux names modes. */
	char digits[2][8];
	unsigned int v[2] = { m->hdisplay, m->vdisplay }, n[2] = { 0, 0 }, at = 0;
	for (int k = 0; k < 2; k++)
		do {
			digits[k][n[k]++] = '0' + v[k] % 10;
			v[k] /= 10;
		} while (v[k]);
	for (int k = 0; k < 2; k++) {
		while (n[k])
			m->name[at++] = digits[k][--n[k]];
		if (k == 0)
			m->name[at++] = 'x';
	}
	m->name[at] = 0;
}

/* Adds a mode to those the connector's get_modes found, once. */
static bool add_probed(struct drm_connector *c, const struct drm_display_mode *mode, u32 type)
{
	for (int i = 0; i < c->lde_probed_count; i++) {
		struct drm_display_mode *m = &c->lde_probed[i];
		if (m->hdisplay == mode->hdisplay && m->vdisplay == mode->vdisplay &&
		    drm_mode_vrefresh(m) == drm_mode_vrefresh(mode)) {
			m->type |= type;
			return false;
		}
	}
	if (c->lde_probed_count == LDE_MAX_MODES)
		return false;
	struct drm_display_mode *m = &c->lde_probed[c->lde_probed_count++];
	*m = *mode;
	m->type = type | DRM_MODE_TYPE_DRIVER;
	name_mode(m);
	return true;
}

int drm_add_modes_noedid(struct drm_connector *connector, int hdisplay, int vdisplay)
{
	int added = 0;
	for (unsigned int i = 0; i < ARRAY_SIZE(dmt); i++)
		if (dmt[i].hdisplay <= hdisplay && dmt[i].vdisplay <= vdisplay)
			added += add_probed(connector, &dmt[i], 0);
	return added;
}

void drm_set_preferred_mode(struct drm_connector *connector, int hpref, int vpref)
{
	for (int i = 0; i < connector->lde_probed_count; i++) {
		struct drm_display_mode *m = &connector->lde_probed[i];
		if (m->hdisplay == hpref && m->vdisplay == vpref)
			m->type |= DRM_MODE_TYPE_PREFERRED;
	}
}

/* ---- EDID */

static const u8 edid_header[8] = { 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 };

int drm_edid_header_is_valid(const void *edid)
{
	const u8 *raw = edid;
	int good = 0;
	for (int i = 0; i < 8; i++)
		good += raw[i] == edid_header[i];
	return good;
}

static bool block_sums_to_zero(const u8 *block)
{
	u8 sum = 0;
	for (int i = 0; i < EDID_LENGTH; i++)
		sum += block[i];
	return sum == 0;
}

/* At most this many extension blocks are read. */
#define MAX_EXTENSIONS 3

struct edid *drm_do_get_edid(struct drm_connector *connector,
			     int (*get_edid_block)(void *data, u8 *buf, unsigned int block, size_t len),
			     void *data)
{
	(void)connector;
	u8 *base = kmalloc(EDID_LENGTH, GFP_KERNEL);
	if (!base)
		return NULL;
	if (get_edid_block(data, base, 0, EDID_LENGTH) || drm_edid_header_is_valid(base) != 8 ||
	    !block_sums_to_zero(base)) {
		kfree(base);
		return NULL;
	}
	unsigned int ext = min_t(unsigned int, base[126], MAX_EXTENSIONS);
	if (!ext)
		return (struct edid *)base;
	u8 *all = kmalloc(EDID_LENGTH * (1 + ext), GFP_KERNEL);
	if (!all)
		return (struct edid *)base;
	memcpy(all, base, EDID_LENGTH);
	kfree(base);
	unsigned int good = 0;
	for (unsigned int b = 1; b <= ext; b++) {
		u8 *block = all + EDID_LENGTH * b;
		if (get_edid_block(data, block, b, EDID_LENGTH) || !block_sums_to_zero(block))
			break;
		good = b;
	}
	/* The blocks that read back whole; the count says so. */
	all[126] = good;
	return (struct edid *)all;
}

/* The mode in a detailed timing descriptor, if it is one. */
static bool detailed_mode(const u8 *d, struct drm_display_mode *m)
{
	unsigned int clock = d[0] | d[1] << 8;
	if (!clock || (d[17] & 0x80)) /* a display descriptor, or interlaced */
		return false;
	unsigned int hactive = d[2] | (d[4] & 0xf0) << 4, hblank = d[3] | (d[4] & 0x0f) << 8;
	unsigned int vactive = d[5] | (d[7] & 0xf0) << 4, vblank = d[6] | (d[7] & 0x0f) << 8;
	unsigned int hso = d[8] | (d[11] & 0xc0) << 2, hspw = d[9] | (d[11] & 0x30) << 4;
	unsigned int vso = (d[10] >> 4) | (d[11] & 0x0c) << 2, vspw = (d[10] & 0x0f) | (d[11] & 0x03) << 4;
	if (!hactive || !vactive || !hblank || !vblank)
		return false;
	memset(m, 0, sizeof(*m));
	m->clock = clock * 10;
	m->hdisplay = hactive;
	m->hsync_start = hactive + hso;
	m->hsync_end = m->hsync_start + hspw;
	m->htotal = hactive + hblank;
	m->vdisplay = vactive;
	m->vsync_start = vactive + vso;
	m->vsync_end = m->vsync_start + vspw;
	m->vtotal = vactive + vblank;
	if ((d[17] & 0x18) == 0x18) {
		m->flags |= d[17] & 0x02 ? PH : NH;
		m->flags |= d[17] & 0x04 ? PV : NV;
	}
	return true;
}

/* The DMT mode of this size and rate, if there is one. */
static const struct drm_display_mode *find_dmt(int w, int h, int hz)
{
	for (unsigned int i = 0; i < ARRAY_SIZE(dmt); i++)
		if (dmt[i].hdisplay == w && dmt[i].vdisplay == h && drm_mode_vrefresh(&dmt[i]) == hz)
			return &dmt[i];
	return NULL;
}

int drm_add_edid_modes(struct drm_connector *connector, struct edid *edid)
{
	if (!edid)
		return 0;
	const u8 *raw = edid->raw;
	int added = 0;
	/* Detailed timings: the first is the preferred mode. */
	for (int k = 0; k < 4; k++) {
		struct drm_display_mode m;
		if (detailed_mode(raw + 54 + 18 * k, &m))
			added += add_probed(connector, &m, k == 0 ? DRM_MODE_TYPE_PREFERRED : 0);
	}
	/* Established timings: bit, size and rate (those VESA's table has). */
	static const struct { u8 byte, bit; u16 w, h; u8 hz; } established[] = {
		{ 35, 5, 640, 480, 60 }, { 35, 3, 640, 480, 72 }, { 35, 2, 640, 480, 75 },
		{ 35, 1, 800, 600, 56 }, { 35, 0, 800, 600, 60 }, { 36, 7, 800, 600, 72 },
		{ 36, 6, 800, 600, 75 }, { 36, 3, 1024, 768, 60 }, { 36, 2, 1024, 768, 70 },
		{ 36, 1, 1024, 768, 75 }, { 36, 0, 1280, 1024, 75 },
	};
	for (unsigned int i = 0; i < ARRAY_SIZE(established); i++) {
		const struct drm_display_mode *m = find_dmt(established[i].w, established[i].h, established[i].hz);
		if (m && (raw[established[i].byte] >> established[i].bit & 1))
			added += add_probed(connector, m, 0);
	}
	/* Standard timings: width, aspect ratio and rate in two bytes. */
	for (int k = 0; k < 8; k++) {
		u8 b0 = raw[38 + 2 * k], b1 = raw[39 + 2 * k];
		if ((b0 == 0x01 && b1 == 0x01) || b0 == 0)
			continue;
		int w = (b0 + 31) * 8, h;
		switch (b1 >> 6) {
		case 0: h = w * 10 / 16; break;
		case 1: h = w * 3 / 4; break;
		case 2: h = w * 4 / 5; break;
		default: h = w * 9 / 16; break;
		}
		const struct drm_display_mode *m = find_dmt(w, h, (b1 & 0x3f) + 60);
		if (m)
			added += add_probed(connector, m, 0);
	}
	return added;
}

int drm_connector_update_edid_property(struct drm_connector *connector, const struct edid *edid)
{
	connector->lde_edid = edid;
	return 0;
}

/* ---- the device */

static struct drm_device *the_device;

struct drm_device *drm_dev_alloc(const struct drm_driver *driver, struct device *parent)
{
	struct drm_device *dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);
	dev->driver = driver;
	dev->dev = parent;
	return dev;
}

int drm_dev_register(struct drm_device *dev, unsigned long flags)
{
	(void)flags;
	if (the_device)
		return -EBUSY;
	the_device = dev;
	dev->registered = true;
	const struct drm_driver *d = dev->driver;
	DRM_INFO("Initialized %s %d.%d.%d %s for %s on minor 0\n", d->name, d->major, d->minor,
		 d->patchlevel, d->date, dev->dev ? dev_name(dev->dev) : "?");
	return 0;
}

void drm_dev_put(struct drm_device *dev)
{
	if (dev == the_device)
		the_device = NULL;
}

void drm_dev_unplug(struct drm_device *dev)
{
	dev->unplugged = true;
}

bool drm_dev_enter(struct drm_device *dev, int *idx)
{
	*idx = 0;
	return !dev->unplugged;
}

void drm_dev_exit(int idx)
{
	(void)idx;
}

void *drmm_kzalloc(struct drm_device *dev, size_t size, gfp_t gfp)
{
	(void)dev;
	return kzalloc(size, gfp);
}

int drmm_mode_config_init(struct drm_device *dev)
{
	memset(&dev->mode_config, 0, sizeof(dev->mode_config));
	return 0;
}

/* ---- the connector */

int drm_connector_init(struct drm_device *dev, struct drm_connector *connector,
		       const struct drm_connector_funcs *funcs, int connector_type)
{
	connector->dev = dev;
	connector->funcs = funcs;
	connector->connector_type = connector_type;
	connector->lde_probed_count = 0;
	connector->lde_mode_count = 0;
	dev->lde_connector = connector;
	return 0;
}

void drm_connector_cleanup(struct drm_connector *connector)
{
	if (connector->dev && connector->dev->lde_connector == connector)
		connector->dev->lde_connector = NULL;
}

void drm_atomic_helper_connector_reset(struct drm_connector *connector)
{
	kfree(connector->state);
	connector->state = kzalloc(sizeof(*connector->state), GFP_KERNEL);
	if (connector->state)
		connector->state->connector = connector;
}

struct drm_connector_state *drm_atomic_helper_connector_duplicate_state(struct drm_connector *connector)
{
	struct drm_connector_state *s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (s && connector->state)
		*s = *connector->state;
	return s;
}

void drm_atomic_helper_connector_destroy_state(struct drm_connector *connector, struct drm_connector_state *state)
{
	(void)connector;
	kfree(state);
}

static enum drm_mode_status mode_status(struct drm_device *dev, const struct drm_display_mode *m)
{
	struct drm_simple_display_pipe *pipe = dev->lde_pipe;
	if (dev->mode_config.funcs && dev->mode_config.funcs->mode_valid) {
		enum drm_mode_status s = dev->mode_config.funcs->mode_valid(dev, m);
		if (s != MODE_OK)
			return s;
	}
	if (pipe && pipe->funcs && pipe->funcs->mode_valid)
		return pipe->funcs->mode_valid(pipe, m);
	return MODE_OK;
}

int drm_helper_probe_single_connector_modes(struct drm_connector *connector, u32 max_width, u32 max_height)
{
	struct drm_device *dev = connector->dev;
	connector->lde_probed_count = 0;
	connector->lde_mode_count = 0;
	if (connector->helper_private && connector->helper_private->get_modes)
		connector->helper_private->get_modes(connector);
	/* Those that fit and the driver takes: preferred first, then the
	 * largest, as Linux sorts them. */
	for (int i = 0; i < connector->lde_probed_count; i++) {
		const struct drm_display_mode *m = &connector->lde_probed[i];
		if ((max_width && m->hdisplay > max_width) || (max_height && m->vdisplay > max_height))
			continue;
		if (m->hdisplay < dev->mode_config.min_width || m->vdisplay < dev->mode_config.min_height)
			continue;
		if (mode_status(dev, m) != MODE_OK)
			continue;
		connector->lde_modes[connector->lde_mode_count++] = *m;
	}
	for (int i = 1; i < connector->lde_mode_count; i++) {
		for (int j = i; j > 0; j--) {
			struct drm_display_mode *a = &connector->lde_modes[j - 1], *b = &connector->lde_modes[j];
			bool ap = a->type & DRM_MODE_TYPE_PREFERRED, bp = b->type & DRM_MODE_TYPE_PREFERRED;
			u32 asz = (u32)a->hdisplay * a->vdisplay, bsz = (u32)b->hdisplay * b->vdisplay;
			bool swap = (bp && !ap) || (ap == bp && (bsz > asz || (bsz == asz &&
				    drm_mode_vrefresh(b) > drm_mode_vrefresh(a))));
			if (!swap)
				break;
			struct drm_display_mode t = *a;
			*a = *b;
			*b = t;
		}
	}
	return connector->lde_mode_count;
}

/* ---- video memory and its buffer objects */

#define PAGE 4096u

int drmm_vram_helper_init(struct drm_device *dev, u64 vram_base, size_t vram_size)
{
	struct lde_vram *v = kzalloc(sizeof(*v), GFP_KERNEL);
	if (!v)
		return -ENOMEM;
	v->base = vram_base;
	v->size = vram_size;
	v->map = ioremap(vram_base, vram_size);
	v->used = kzalloc(vram_size / PAGE, GFP_KERNEL);
	if (!v->map || !v->used) {
		kfree(v->used);
		kfree(v);
		return -ENOMEM;
	}
	dev->vram_mm = v;
	return 0;
}

enum drm_mode_status drm_vram_helper_mode_valid(struct drm_device *dev, const struct drm_display_mode *mode)
{
	/* Two framebuffers of 32-bit pixels must fit, as Linux's helper
	 * asks, so one can be drawn while the other is shown. */
	struct lde_vram *v = dev->vram_mm;
	u64 pages = ((u64)mode->hdisplay * mode->vdisplay * 4 + PAGE - 1) / PAGE;
	if (!v || pages > (v->size / 2) / PAGE)
		return MODE_MEM;
	return MODE_OK;
}

static struct drm_gem_vram_object *vram_create(struct drm_device *dev, size_t size)
{
	struct lde_vram *v = dev->vram_mm;
	if (!v)
		return NULL;
	unsigned int pages = (size + PAGE - 1) / PAGE, total = v->size / PAGE;
	for (unsigned int first = 0; first + pages <= total; first++) {
		unsigned int p = first;
		while (p < first + pages && !v->used[p])
			p++;
		if (p < first + pages) {
			first = p;
			continue;
		}
		struct drm_gem_vram_object *gbo = kzalloc(sizeof(*gbo), GFP_KERNEL);
		if (!gbo)
			return NULL;
		memset(v->used + first, 1, pages);
		gbo->bo.base.dev = dev;
		gbo->bo.base.size = (size_t)pages * PAGE;
		gbo->offset = (u64)first * PAGE;
		return gbo;
	}
	return NULL;
}

static void vram_free(struct drm_gem_vram_object *gbo)
{
	struct lde_vram *v = gbo->bo.base.dev->vram_mm;
	memset(v->used + gbo->offset / PAGE, 0, gbo->bo.base.size / PAGE);
	kfree(gbo);
}

s64 drm_gem_vram_offset(struct drm_gem_vram_object *gbo)
{
	return gbo->pin_count ? (s64)gbo->offset : -ENODEV;
}

int drm_gem_vram_simple_display_pipe_prepare_fb(struct drm_simple_display_pipe *pipe,
						struct drm_plane_state *new_state)
{
	(void)pipe;
	if (new_state->fb)
		drm_gem_vram_of_gem(new_state->fb->obj[0])->pin_count++;
	return 0;
}

void drm_gem_vram_simple_display_pipe_cleanup_fb(struct drm_simple_display_pipe *pipe,
						 struct drm_plane_state *old_state)
{
	(void)pipe;
	if (old_state->fb)
		drm_gem_vram_of_gem(old_state->fb->obj[0])->pin_count--;
}

/* Handles: the host's buffer objects, numbered from 1. */
#define MAX_OBJECTS 4
static struct drm_gem_object *objects[MAX_OBJECTS];

struct drm_framebuffer *drm_gem_fb_create(struct drm_device *dev, struct drm_file *file,
					  const struct drm_mode_fb_cmd2 *cmd)
{
	(void)file;
	u32 h = cmd->handles[0];
	if (!h || h > MAX_OBJECTS || !objects[h - 1])
		return ERR_PTR(-ENOENT);
	struct drm_gem_object *obj = objects[h - 1];
	const struct drm_format_info *format = drm_format_info(cmd->pixel_format);
	if (!format || format->num_planes != 1)
		return ERR_PTR(-EINVAL);
	if (cmd->pitches[0] < cmd->width * format->cpp[0] ||
	    (u64)cmd->offsets[0] + (u64)cmd->pitches[0] * cmd->height > obj->size)
		return ERR_PTR(-EINVAL);
	struct drm_framebuffer *fb = kzalloc(sizeof(*fb), GFP_KERNEL);
	if (!fb)
		return ERR_PTR(-ENOMEM);
	fb->dev = dev;
	fb->format = format;
	fb->width = cmd->width;
	fb->height = cmd->height;
	fb->pitches[0] = cmd->pitches[0];
	fb->offsets[0] = cmd->offsets[0];
	fb->modifier = DRM_FORMAT_MOD_LINEAR;
	fb->obj[0] = obj;
	return fb;
}

/* ---- the pipeline and its commits */

int drm_simple_display_pipe_init(struct drm_device *dev, struct drm_simple_display_pipe *pipe,
				 const struct drm_simple_display_pipe_funcs *funcs, const u32 *formats_,
				 unsigned int format_count, const u64 *format_modifiers,
				 struct drm_connector *connector)
{
	(void)format_modifiers;
	pipe->funcs = funcs;
	pipe->connector = connector;
	pipe->plane.dev = dev;
	pipe->plane.format_types = formats_;
	pipe->plane.format_count = format_count;
	pipe->crtc.dev = dev;
	pipe->crtc.primary = &pipe->plane;
	pipe->encoder.dev = dev;
	pipe->encoder.possible_crtcs = 1;
	dev->lde_pipe = pipe;
	return 0;
}

void drm_mode_config_reset(struct drm_device *dev)
{
	struct drm_simple_display_pipe *pipe = dev->lde_pipe;
	if (pipe) {
		kfree(pipe->plane.state);
		kfree(pipe->crtc.state);
		pipe->plane.state = kzalloc(sizeof(*pipe->plane.state), GFP_KERNEL);
		pipe->crtc.state = kzalloc(sizeof(*pipe->crtc.state), GFP_KERNEL);
		if (pipe->plane.state)
			pipe->plane.state->plane = &pipe->plane;
		if (pipe->crtc.state)
			pipe->crtc.state->crtc = &pipe->crtc;
	}
	struct drm_connector *c = dev->lde_connector;
	if (c && c->funcs && c->funcs->reset)
		c->funcs->reset(c);
}

static bool format_allowed(const struct drm_plane *plane, u32 format)
{
	for (unsigned int i = 0; i < plane->format_count; i++)
		if (plane->format_types[i] == format)
			return true;
	return false;
}

int drm_atomic_helper_check(struct drm_device *dev, struct drm_atomic_state *state)
{
	struct drm_simple_display_pipe *pipe = dev->lde_pipe;
	struct drm_crtc_state *c = state->new_crtc_state;
	struct drm_plane_state *p = state->new_plane_state;
	if (!c->enable) {
		p->visible = false;
		return p->fb ? -EINVAL : 0;
	}
	if (mode_status(dev, &c->mode) != MODE_OK)
		return -EINVAL;
	/* The primary plane covers the CRTC, unscaled. */
	if (!p->fb || !format_allowed(&pipe->plane, p->fb->format->format) ||
	    p->fb->width < c->mode.hdisplay || p->fb->height < c->mode.vdisplay)
		return -EINVAL;
	p->crtc = &pipe->crtc;
	p->crtc_x = p->crtc_y = 0;
	p->crtc_w = c->mode.hdisplay;
	p->crtc_h = c->mode.vdisplay;
	p->src_x = p->src_y = 0;
	p->src_w = c->mode.hdisplay << 16;
	p->src_h = c->mode.vdisplay << 16;
	p->visible = true;
	if (pipe->funcs && pipe->funcs->check)
		return pipe->funcs->check(pipe, p, c);
	return 0;
}

int drm_atomic_helper_commit(struct drm_device *dev, struct drm_atomic_state *state, bool nonblock)
{
	(void)nonblock;
	struct drm_simple_display_pipe *pipe = dev->lde_pipe;
	const struct drm_simple_display_pipe_funcs *f = pipe->funcs;
	struct drm_crtc_state *oc = state->old_crtc_state, *nc = state->new_crtc_state;
	struct drm_plane_state *op = state->old_plane_state, *np = state->new_plane_state;
	bool modeset = oc->enable != nc->enable || nc->mode_changed;
	if (np->fb && f->prepare_fb) {
		int rc = f->prepare_fb(pipe, np);
		if (rc)
			return rc;
	}
	/* Linux's commit tail: disables, then planes, then enables. */
	if (oc->enable && modeset && f->disable)
		f->disable(pipe);
	pipe->plane.state = np;
	pipe->crtc.state = nc;
	if (nc->enable && f->update)
		f->update(pipe, op);
	if (nc->enable && modeset && f->enable)
		f->enable(pipe, nc, np);
	if (op->fb && f->cleanup_fb)
		f->cleanup_fb(pipe, op);
	kfree(op);
	kfree(oc);
	return 0;
}

/* Checks and commits the pipeline showing `fb` in `mode` (NULL: off). */
static int commit(struct drm_device *dev, struct drm_framebuffer *fb, const struct drm_display_mode *mode)
{
	struct drm_simple_display_pipe *pipe = dev->lde_pipe;
	const struct drm_mode_config_funcs *funcs = dev->mode_config.funcs;
	if (!pipe || !pipe->plane.state || !pipe->crtc.state || !funcs || !funcs->atomic_commit)
		return -ENODEV;
	struct drm_plane_state *np = kmalloc(sizeof(*np), GFP_KERNEL);
	struct drm_crtc_state *nc = kmalloc(sizeof(*nc), GFP_KERNEL);
	if (!np || !nc) {
		kfree(np);
		kfree(nc);
		return -ENOMEM;
	}
	*np = *pipe->plane.state;
	*nc = *pipe->crtc.state;
	np->fb = fb;
	nc->enable = nc->active = mode != NULL;
	nc->mode_changed = false;
	if (mode) {
		const struct drm_display_mode *was = &pipe->crtc.state->mode;
		nc->mode_changed = !pipe->crtc.state->enable || was->hdisplay != mode->hdisplay ||
				   was->vdisplay != mode->vdisplay || was->clock != mode->clock;
		nc->mode = *mode;
	}
	struct drm_atomic_state state = {
		.dev = dev,
		.plane = &pipe->plane,
		.crtc = &pipe->crtc,
		.old_plane_state = pipe->plane.state,
		.new_plane_state = np,
		.old_crtc_state = pipe->crtc.state,
		.new_crtc_state = nc,
	};
	np->state = nc->state = &state;
	int rc = funcs->atomic_check ? funcs->atomic_check(dev, &state) : 0;
	if (!rc)
		rc = funcs->atomic_commit(dev, &state, false);
	if (rc) {
		kfree(np);
		kfree(nc);
		return rc;
	}
	np->state = nc->state = NULL;
	return 0;
}

void drm_atomic_helper_shutdown(struct drm_device *dev)
{
	commit(dev, NULL, NULL);
}

/* ---- for the host (lde/host.h) */

static struct drm_framebuffer *buffers[2];

static struct drm_connector *connector(void)
{
	return the_device && the_device->registered ? the_device->lde_connector : NULL;
}

int lde_drm_probe(void)
{
	struct drm_connector *c = connector();
	if (!c || !c->funcs || !c->funcs->fill_modes)
		return -ENODEV;
	const struct drm_mode_config *mc = &the_device->mode_config;
	return c->funcs->fill_modes(c, mc->max_width, mc->max_height);
}

int lde_drm_edid(void)
{
	struct drm_connector *c = connector();
	return c && c->lde_edid;
}

int lde_drm_mode(unsigned int i, u32 *width, u32 *height, u32 *refresh, u32 *preferred)
{
	struct drm_connector *c = connector();
	if (!c || i >= (unsigned int)c->lde_mode_count)
		return 0;
	const struct drm_display_mode *m = &c->lde_modes[i];
	*width = m->hdisplay;
	*height = m->vdisplay;
	*refresh = drm_mode_vrefresh(m);
	*preferred = !!(m->type & DRM_MODE_TYPE_PREFERRED);
	return 1;
}

static void drop_buffers(void)
{
	for (int b = 0; b < 2; b++) {
		if (!buffers[b])
			continue;
		struct drm_gem_vram_object *gbo = drm_gem_vram_of_gem(buffers[b]->obj[0]);
		for (int h = 0; h < MAX_OBJECTS; h++)
			if (objects[h] == &gbo->bo.base)
				objects[h] = NULL;
		vram_free(gbo);
		kfree(buffers[b]);
		buffers[b] = NULL;
	}
}

int lde_drm_start(unsigned int i, u32 *pitch)
{
	struct drm_connector *c = connector();
	if (!c || i >= (unsigned int)c->lde_mode_count || !the_device->mode_config.funcs->fb_create)
		return -EINVAL;
	const struct drm_display_mode mode = c->lde_modes[i];
	/* Off first, so the old buffers are unpinned and can go. */
	if (buffers[0]) {
		int rc = commit(the_device, NULL, NULL);
		if (rc)
			return rc;
		drop_buffers();
	}
	struct drm_mode_fb_cmd2 cmd = {
		.width = mode.hdisplay,
		.height = mode.vdisplay,
		.pixel_format = DRM_FORMAT_XRGB8888,
		.pitches = { mode.hdisplay * 4 },
	};
	for (int b = 0; b < 2; b++) {
		struct drm_gem_vram_object *gbo = vram_create(the_device, (size_t)cmd.pitches[0] * cmd.height);
		if (!gbo) {
			drop_buffers();
			return -ENOMEM;
		}
		objects[b] = &gbo->bo.base;
		cmd.handles[0] = b + 1;
		/* The driver's fb_create, as userspace's ADDFB2 would call it. */
		struct drm_framebuffer *fb = the_device->mode_config.funcs->fb_create(the_device, NULL, &cmd);
		if (IS_ERR(fb)) {
			vram_free(gbo);
			objects[b] = NULL;
			drop_buffers();
			return PTR_ERR(fb);
		}
		buffers[b] = fb;
		/* Black to begin with. */
		u32 __iomem *px = (u32 __iomem *)(the_device->vram_mm->map + gbo->offset);
		for (size_t k = 0; k < gbo->bo.base.size / 4; k++)
			writel(0, px + k);
	}
	int rc = commit(the_device, buffers[0], &mode);
	if (rc) {
		drop_buffers();
		return rc;
	}
	*pitch = cmd.pitches[0];
	return 0;
}

void *lde_drm_buffer(int b)
{
	if (b < 0 || b > 1 || !buffers[b])
		return NULL;
	struct drm_gem_vram_object *gbo = drm_gem_vram_of_gem(buffers[b]->obj[0]);
	return the_device->vram_mm->map + gbo->offset;
}

u64 lde_drm_buffer_offset(int b)
{
	if (b < 0 || b > 1 || !buffers[b])
		return ~0ull;
	return drm_gem_vram_of_gem(buffers[b]->obj[0])->offset;
}

int lde_drm_flip(int b)
{
	struct drm_simple_display_pipe *pipe = the_device ? the_device->lde_pipe : NULL;
	if (b < 0 || b > 1 || !buffers[b] || !pipe || !pipe->crtc.state || !pipe->crtc.state->enable)
		return -EINVAL;
	struct drm_display_mode mode = pipe->crtc.state->mode;
	return commit(the_device, buffers[b], &mode);
}
