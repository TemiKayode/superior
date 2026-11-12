/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* VGA's registers, as Linux's <video/vga.h> names them (the ones the
 * hosted display drivers use). Written for Superior. */
#ifndef LDE_VIDEO_VGA_H
#define LDE_VIDEO_VGA_H

#include <lde/linux.h>

#define VGA_ATT_W 0x3c0
#define VGA_MIS_W 0x3c2
#define VGA_IS1_RC 0x3da
#define VGA_MIS_COLOR 0x01
#define VGA_AR_ENABLE_DISPLAY 0x20

#endif
