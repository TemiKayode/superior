/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * Between the two halves of the Linux Driver Environment: what lde.c asks
 * of the Rust host (crates/lde/src/lib.rs), which holds the component's
 * capabilities, and what the host calls in lde.c to run the driver.
 */
#ifndef LDE_HOST_H
#define LDE_HOST_H

#include <lde/linux.h>

/* ---- the host's, for lde.c */

/* Zeroed memory the device can reach, aligned to 64 bytes (to a page, if
 * larger than 2048 bytes); NULL if there is none. */
void *lde_host_alloc(size_t size);
void lde_host_free(const void *p);
/* The address the device uses for `size` bytes at `p`, which must lie in
 * memory from lde_host_alloc; ~0 if they are not contiguous for it. */
u64 lde_host_dma(const void *p, size_t size);
/* One line for the log. */
void lde_host_log(const char *line, size_t len);
/* A dword of the device's configuration space. */
u32 lde_host_config_read(unsigned int offset);
/* Where the device is: bus << 8 | device << 3 | function. */
u32 lde_host_location(void);
/* Memory BAR `bar`: its size (0 if there is none), and its registers
 * mapped (NULL on failure). */
u64 lde_host_bar_size(unsigned int bar);
void *lde_host_bar_map(unsigned int bar);
/* Reads (`write` 0, into `*value`) or writes `width` bytes (1, 2 or 4) at
 * `offset` in I/O BAR `bar`, through the bus server. 0 or -errno. */
int lde_host_io(unsigned int bar, unsigned int offset, unsigned int width, int write, u32 value, u32 *value_out);
/* Lets the device do DMA. 0 or -errno. */
int lde_host_bus_master(int on);
/* Has the device's interrupt line delivered to the component's loop,
 * which then calls lde_interrupt. 0 or -errno. */
int lde_host_irq(int on);
void lde_host_sleep(unsigned long ticks);
void lde_host_udelay(unsigned long usecs);
/* A received frame (a whole Ethernet frame), copied before it returns. */
void lde_host_rx(const void *frame, size_t len);

/* ---- lde.c's, for the host */

/* Runs the driver's module initialisation: it registers itself. */
int lde_module_init(void);
/* The `i`th device the driver says it drives; 0 past the last. */
int lde_device_id(unsigned int i, u16 *vendor, u16 *device);
/* The host has opened a device with these IDs, whose memory BARs are
 * `bars` (a bitmask): the driver's probe. 0 or -errno. */
int lde_probe(u16 vendor, u16 device, u32 bars);
/* Brings the registered network interface up. 0 or -errno. */
int lde_open(void);
/* The interrupt line signalled: the driver's handler. */
void lde_interrupt(void);
/* Whether a receive poll is waiting to be run, and running it: frames
 * arrive through lde_host_rx, at most `lde_poll_weight()` a call. */
int lde_poll_pending(void);
int lde_poll_weight(void);
void lde_poll(void);
/* Sends a frame: 0, 1 if the driver's queue is full for now, or -errno. */
int lde_xmit(const void *frame, size_t len);
/* Runs the driver's kernel timers and work that are due (lde.c). */
void lde_run_timers(void);
/* Runs the driver's timers and work that are due, and the transmit
 * watchdog; and how many ticks until it must be called again (0: only
 * when something else happens). */
void lde_tick(void);
unsigned long lde_next_timer(void);
/* The interface's MAC address (6 bytes) and whether its link is up. */
void lde_mac(u8 *mac);
int lde_carrier(void);

/* ---- lde-drm.c's, for a display driver's host */

/* Asks the connector for its modes (the driver's get_modes, filtered by
 * its mode_valid): how many, or -errno. */
int lde_drm_probe(void);
/* Whether the driver read the display's EDID. */
int lde_drm_edid(void);
/* Mode `i` (preferred first): 1, or 0 past the last. */
int lde_drm_mode(unsigned int i, u32 *width, u32 *height, u32 *refresh, u32 *preferred);
/* Makes two XRGB8888 framebuffers in video memory for mode `i` (the
 * driver's fb_create) and commits the mode showing the first: its pitch,
 * 0 or -errno. */
int lde_drm_start(unsigned int i, u32 *pitch);
/* Framebuffer `b`'s pixels (device memory) and offset in video memory. */
void *lde_drm_buffer(int b);
u64 lde_drm_buffer_offset(int b);
/* Commits framebuffer `b` as the one shown: 0 or -errno. */
int lde_drm_flip(int b);

#endif
