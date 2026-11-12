/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * The Linux Driver Environment's sound: the part of Linux's ALSA API a
 * hosted PCI sound driver uses, written for Superior. As with lde/linux.h,
 * the names and meanings are Linux's, so a driver compiles unchanged; the
 * implementation is lde-snd.c's.
 *
 * Every <sound/...> header a driver includes is this file. A driver makes
 * one card with its mixer controls, PCM devices and MIDI ports; userspace
 * is the Rust host, which opens one playback stream at a time: it picks
 * the format (signed 16-bit stereo), rate, buffer and period, checks them
 * against what the driver says its hardware takes, and gives the driver
 * the buffer (ALSA's "managed" buffer, in memory the device reaches).
 * Controls are kept and can be set by name; MIDI ports exist but nothing
 * plays through them; /proc text has nowhere to go.
 */
#ifndef LDE_SOUND_H
#define LDE_SOUND_H

#include <lde/linux.h>

/* ---- cards (initval.h, core.h) */

#define SNDRV_CARDS 8
#define SNDRV_DEFAULT_IDX { [0 ... (SNDRV_CARDS - 1)] = -1 }
#define SNDRV_DEFAULT_STR { [0 ... (SNDRV_CARDS - 1)] = NULL }
#define SNDRV_DEFAULT_ENABLE_PNP { [0 ... (SNDRV_CARDS - 1)] = 1 }
#define SNDRV_DEFAULT_ENABLE SNDRV_DEFAULT_ENABLE_PNP

#define snd_BUG() ((void)_printk("sound: BUG? at %s:%d\n", __FILE__, __LINE__))
#define snd_BUG_ON(c) WARN_ON(c)

struct snd_kcontrol;
struct snd_device;
struct snd_pcm;
struct snd_rawmidi;

struct snd_card {
	int number;
	char id[16];
	char driver[16];
	char shortname[32];
	char longname[80];
	char mixername[80];
	char components[128];
	struct device *dev;
	void *private_data;
	void (*private_free)(struct snd_card *card);
	int sync_irq;
	/* lde-snd.c's: what the driver made. */
	struct snd_kcontrol *lde_controls;
	struct snd_device *lde_devices;
	struct snd_pcm *lde_pcms;
	struct snd_rawmidi *lde_midis;
	bool lde_registered;
};

/* The card lives as long as the component (devm). */
int snd_devm_card_new(struct device *parent, int idx, const char *xid, struct module *module,
		      size_t extra_size, struct snd_card **card_ret);
int snd_card_register(struct snd_card *card);
int snd_card_free_on_error(struct device *dev, int ret);
int snd_component_add(struct snd_card *card, const char *component);

#define SNDRV_CTL_POWER_D0 0x0000
#define SNDRV_CTL_POWER_D3hot 0x0300
static inline void snd_power_change_state(struct snd_card *card, unsigned int state)
{
	(void)card; (void)state;
}

enum snd_device_type {
	SNDRV_DEV_LOWLEVEL,
	SNDRV_DEV_INFO,
	SNDRV_DEV_BUS,
	SNDRV_DEV_CODEC,
	SNDRV_DEV_PCM,
	SNDRV_DEV_COMPRESS,
	SNDRV_DEV_RAWMIDI,
	SNDRV_DEV_TIMER,
	SNDRV_DEV_SEQUENCER,
	SNDRV_DEV_HWDEP,
	SNDRV_DEV_JACK,
	SNDRV_DEV_CONTROL,
};
struct snd_device_ops {
	int (*dev_free)(struct snd_device *dev);
	int (*dev_register)(struct snd_device *dev);
	int (*dev_disconnect)(struct snd_device *dev);
};
struct snd_device {
	struct snd_card *card;
	enum snd_device_type type;
	void *device_data;
	const struct snd_device_ops *ops;
	struct snd_device *lde_next;
};
int snd_device_new(struct snd_card *card, enum snd_device_type type, void *device_data,
		   const struct snd_device_ops *ops);

/* ---- /proc text (info.h): nowhere to go */

struct snd_info_buffer;
struct snd_info_entry {
	void *private_data;
};
static inline int snd_card_ro_proc_new(struct snd_card *card, const char *name, void *private_data,
				       void (*read)(struct snd_info_entry *, struct snd_info_buffer *))
{
	(void)card; (void)name; (void)private_data; (void)read;
	return 0;
}
static inline __printf(2, 3) int snd_iprintf(struct snd_info_buffer *buffer, const char *fmt, ...)
{
	(void)buffer; (void)fmt;
	return 0;
}

/* ---- controls (control.h, tlv.h) */

typedef int snd_ctl_elem_type_t;
typedef int snd_ctl_elem_iface_t;
#define SNDRV_CTL_ELEM_TYPE_NONE 0
#define SNDRV_CTL_ELEM_TYPE_BOOLEAN 1
#define SNDRV_CTL_ELEM_TYPE_INTEGER 2
#define SNDRV_CTL_ELEM_TYPE_ENUMERATED 3
#define SNDRV_CTL_ELEM_TYPE_BYTES 4
#define SNDRV_CTL_ELEM_TYPE_IEC958 5
#define SNDRV_CTL_ELEM_TYPE_INTEGER64 6
#define SNDRV_CTL_ELEM_IFACE_CARD 0
#define SNDRV_CTL_ELEM_IFACE_HWDEP 1
#define SNDRV_CTL_ELEM_IFACE_MIXER 2
#define SNDRV_CTL_ELEM_IFACE_PCM 3
#define SNDRV_CTL_ELEM_IFACE_RAWMIDI 4
#define SNDRV_CTL_ELEM_ACCESS_READ (1 << 0)
#define SNDRV_CTL_ELEM_ACCESS_WRITE (1 << 1)
#define SNDRV_CTL_ELEM_ACCESS_READWRITE (SNDRV_CTL_ELEM_ACCESS_READ | SNDRV_CTL_ELEM_ACCESS_WRITE)
#define SNDRV_CTL_ELEM_ACCESS_VOLATILE (1 << 2)
#define SNDRV_CTL_ELEM_ACCESS_TLV_READ (1 << 4)
#define SNDRV_CTL_ELEM_ACCESS_TLV_WRITE (1 << 5)
#define SNDRV_CTL_ELEM_ACCESS_TLV_READWRITE (SNDRV_CTL_ELEM_ACCESS_TLV_READ | SNDRV_CTL_ELEM_ACCESS_TLV_WRITE)
#define SNDRV_CTL_ELEM_ACCESS_INACTIVE (1 << 8)
#define SNDRV_CTL_TLVT_DB_SCALE 1
#define SNDRV_CTL_TLVD_DB_SCALE_MUTE 0x10000
#define DECLARE_TLV_DB_SCALE(name, min, step, mute) \
	unsigned int name[] = { SNDRV_CTL_TLVT_DB_SCALE, 2 * sizeof(unsigned int), \
				(min), ((step) & 0xffff) | ((mute) ? SNDRV_CTL_TLVD_DB_SCALE_MUTE : 0) }

struct snd_ctl_elem_id {
	unsigned int numid;
	snd_ctl_elem_iface_t iface;
	unsigned int device, subdevice;
	char name[44];
	unsigned int index;
};
struct snd_ctl_elem_info {
	struct snd_ctl_elem_id id;
	snd_ctl_elem_type_t type;
	unsigned int access;
	unsigned int count;
	union {
		struct { long min, max, step; } integer;
		struct { long long min, max, step; } integer64;
		struct { unsigned int items, item; char name[64]; } enumerated;
	} value;
};
struct snd_ctl_elem_value {
	struct snd_ctl_elem_id id;
	union {
		union { long value[128]; } integer;
		union { long long value[64]; } integer64;
		union { unsigned int item[128]; } enumerated;
		union { unsigned char data[512]; } bytes;
	} value;
};
typedef int(snd_kcontrol_info_t)(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_info *uinfo);
typedef int(snd_kcontrol_get_t)(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_value *ucontrol);
typedef int(snd_kcontrol_put_t)(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_value *ucontrol);
typedef int(snd_kcontrol_tlv_rw_t)(struct snd_kcontrol *kcontrol, int op_flag, unsigned int size,
				   unsigned int __user *tlv);
struct snd_kcontrol_new {
	snd_ctl_elem_iface_t iface;
	unsigned int device, subdevice;
	const char *name;
	unsigned int index;
	unsigned int access;
	unsigned int count;
	snd_kcontrol_info_t *info;
	snd_kcontrol_get_t *get;
	snd_kcontrol_put_t *put;
	union {
		snd_kcontrol_tlv_rw_t *c;
		const unsigned int *p;
	} tlv;
	unsigned long private_value;
};
struct snd_kcontrol {
	struct snd_ctl_elem_id id;
	unsigned int count;
	unsigned int access;
	snd_kcontrol_info_t *info;
	snd_kcontrol_get_t *get;
	snd_kcontrol_put_t *put;
	union {
		snd_kcontrol_tlv_rw_t *c;
		const unsigned int *p;
	} tlv;
	unsigned long private_value;
	void *private_data;
	void (*private_free)(struct snd_kcontrol *kcontrol);
	struct snd_kcontrol *lde_next;
};
#define snd_kcontrol_chip(kcontrol) ((kcontrol)->private_data)
struct snd_kcontrol *snd_ctl_new1(const struct snd_kcontrol_new *kcontrolnew, void *private_data);
int snd_ctl_add(struct snd_card *card, struct snd_kcontrol *kcontrol);
int snd_ctl_boolean_mono_info(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_info *uinfo);
int snd_ctl_boolean_stereo_info(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_info *uinfo);

/* ---- PCM (pcm.h) */

typedef unsigned long snd_pcm_uframes_t;
typedef long snd_pcm_sframes_t;
typedef int snd_pcm_format_t;
#define SNDRV_PCM_FORMAT_S8 0
#define SNDRV_PCM_FORMAT_U8 1
#define SNDRV_PCM_FORMAT_S16_LE 2
#define SNDRV_PCM_FORMAT_S16_BE 3
#define SNDRV_PCM_FORMAT_U16_LE 4
#define SNDRV_PCM_FORMAT_U16_BE 5
#define SNDRV_PCM_FORMAT_S32_LE 10
#define SNDRV_PCM_FMTBIT_S8 (1ULL << SNDRV_PCM_FORMAT_S8)
#define SNDRV_PCM_FMTBIT_U8 (1ULL << SNDRV_PCM_FORMAT_U8)
#define SNDRV_PCM_FMTBIT_S16_LE (1ULL << SNDRV_PCM_FORMAT_S16_LE)
#define SNDRV_PCM_FMTBIT_S16_BE (1ULL << SNDRV_PCM_FORMAT_S16_BE)
#define SNDRV_PCM_FMTBIT_S32_LE (1ULL << SNDRV_PCM_FORMAT_S32_LE)

#define SNDRV_PCM_RATE_5512 (1u << 0)
#define SNDRV_PCM_RATE_8000 (1u << 1)
#define SNDRV_PCM_RATE_11025 (1u << 2)
#define SNDRV_PCM_RATE_16000 (1u << 3)
#define SNDRV_PCM_RATE_22050 (1u << 4)
#define SNDRV_PCM_RATE_32000 (1u << 5)
#define SNDRV_PCM_RATE_44100 (1u << 6)
#define SNDRV_PCM_RATE_48000 (1u << 7)
#define SNDRV_PCM_RATE_64000 (1u << 8)
#define SNDRV_PCM_RATE_88200 (1u << 9)
#define SNDRV_PCM_RATE_96000 (1u << 10)
#define SNDRV_PCM_RATE_176400 (1u << 11)
#define SNDRV_PCM_RATE_192000 (1u << 12)
#define SNDRV_PCM_RATE_CONTINUOUS (1u << 30)
#define SNDRV_PCM_RATE_KNOT (1u << 31)
#define SNDRV_PCM_RATE_8000_44100 (SNDRV_PCM_RATE_8000 | SNDRV_PCM_RATE_11025 | SNDRV_PCM_RATE_16000 | \
				   SNDRV_PCM_RATE_22050 | SNDRV_PCM_RATE_32000 | SNDRV_PCM_RATE_44100)
#define SNDRV_PCM_RATE_8000_48000 (SNDRV_PCM_RATE_8000_44100 | SNDRV_PCM_RATE_48000)

#define SNDRV_PCM_INFO_MMAP 0x00000001
#define SNDRV_PCM_INFO_MMAP_VALID 0x00000002
#define SNDRV_PCM_INFO_DOUBLE 0x00000004
#define SNDRV_PCM_INFO_BATCH 0x00000010
#define SNDRV_PCM_INFO_INTERLEAVED 0x00000100
#define SNDRV_PCM_INFO_NONINTERLEAVED 0x00000200
#define SNDRV_PCM_INFO_BLOCK_TRANSFER 0x00010000
#define SNDRV_PCM_INFO_OVERRANGE 0x00020000
#define SNDRV_PCM_INFO_RESUME 0x00040000
#define SNDRV_PCM_INFO_PAUSE 0x00080000
#define SNDRV_PCM_INFO_HALF_DUPLEX 0x00100000
#define SNDRV_PCM_INFO_JOINT_DUPLEX 0x00200000
#define SNDRV_PCM_INFO_SYNC_START 0x00400000

#define SNDRV_PCM_STREAM_PLAYBACK 0
#define SNDRV_PCM_STREAM_CAPTURE 1
#define SNDRV_PCM_TRIGGER_STOP 0
#define SNDRV_PCM_TRIGGER_START 1
#define SNDRV_PCM_TRIGGER_PAUSE_PUSH 3
#define SNDRV_PCM_TRIGGER_PAUSE_RELEASE 4
#define SNDRV_PCM_TRIGGER_SUSPEND 5
#define SNDRV_PCM_TRIGGER_RESUME 6

#define SNDRV_PCM_HW_PARAM_ACCESS 0
#define SNDRV_PCM_HW_PARAM_FORMAT 1
#define SNDRV_PCM_HW_PARAM_CHANNELS 10
#define SNDRV_PCM_HW_PARAM_RATE 11
#define SNDRV_PCM_HW_PARAM_PERIOD_SIZE 13
#define SNDRV_PCM_HW_PARAM_PERIOD_BYTES 14
#define SNDRV_PCM_HW_PARAM_BUFFER_SIZE 17
#define SNDRV_PCM_HW_PARAM_BUFFER_BYTES 18

#define SNDRV_DMA_TYPE_CONTINUOUS 1
#define SNDRV_DMA_TYPE_DEV 2

struct snd_pcm_hardware {
	unsigned int info;
	u64 formats;
	unsigned int rates;
	unsigned int rate_min, rate_max;
	unsigned int channels_min, channels_max;
	size_t buffer_bytes_max;
	size_t period_bytes_min, period_bytes_max;
	unsigned int periods_min, periods_max;
	size_t fifo_size;
};
struct snd_pcm_hw_constraint_list {
	unsigned int count;
	const unsigned int *list;
	unsigned int mask;
};
struct snd_ratnum {
	unsigned int num, den_min, den_max, den_step;
};
struct snd_ratden {
	unsigned int num_min, num_max, num_step, den;
};
struct snd_pcm_hw_constraint_ratnums {
	int nrats;
	const struct snd_ratnum *rats;
};
struct snd_pcm_hw_constraint_ratdens {
	int nrats;
	const struct snd_ratden *rats;
};

struct snd_dma_buffer {
	struct {
		int type;
		struct device *dev;
	} dev;
	unsigned char *area;
	dma_addr_t addr;
	size_t bytes;
	void *private_data;
};
struct snd_dma_buffer *snd_devm_alloc_pages(struct device *dev, int type, size_t size);

/* The rate constraints a driver's open adds: lde-snd.c checks a rate
 * against each. */
#define LDE_SND_CONSTRAINTS 4
struct lde_snd_constraint {
	int kind; /* 1 a list, 2 ratnums, 3 ratdens */
	const void *what;
};

struct snd_pcm_runtime {
	snd_pcm_format_t format;
	unsigned int rate;
	unsigned int channels;
	unsigned int frame_bits;
	unsigned int sample_bits;
	snd_pcm_uframes_t period_size;
	unsigned int periods;
	snd_pcm_uframes_t buffer_size;
	unsigned char *dma_area;
	dma_addr_t dma_addr;
	size_t dma_bytes;
	struct snd_pcm_hardware hw;
	void *private_data;
	void (*private_free)(struct snd_pcm_runtime *runtime);
	struct lde_snd_constraint lde_rates[LDE_SND_CONSTRAINTS];
	unsigned int lde_constraints;
};
struct snd_pcm_ops;
struct snd_pcm_substream {
	struct snd_pcm *pcm;
	int stream;
	int number;
	char name[32];
	void *private_data;
	const struct snd_pcm_ops *ops;
	struct snd_pcm_runtime *runtime;
	/* lde-snd.c's: the managed buffer's sizes; periods elapsed. */
	size_t lde_buffer_size, lde_buffer_max;
	unsigned long lde_periods;
};
struct snd_pcm_hw_params;
struct snd_pcm_ops {
	int (*open)(struct snd_pcm_substream *substream);
	int (*close)(struct snd_pcm_substream *substream);
	int (*ioctl)(struct snd_pcm_substream *substream, unsigned int cmd, void *arg);
	int (*hw_params)(struct snd_pcm_substream *substream, struct snd_pcm_hw_params *params);
	int (*hw_free)(struct snd_pcm_substream *substream);
	int (*prepare)(struct snd_pcm_substream *substream);
	int (*trigger)(struct snd_pcm_substream *substream, int cmd);
	int (*sync_stop)(struct snd_pcm_substream *substream);
	snd_pcm_uframes_t (*pointer)(struct snd_pcm_substream *substream);
};
#define LDE_SND_SUBSTREAMS 2
struct snd_pcm {
	struct snd_card *card;
	int device;
	char id[64];
	char name[80];
	unsigned int info_flags;
	void *private_data;
	void (*private_free)(struct snd_pcm *pcm);
	/* lde-snd.c's: each direction's substreams. */
	unsigned int lde_count[2];
	struct snd_pcm_substream lde_sub[2][LDE_SND_SUBSTREAMS];
	struct snd_pcm *lde_next;
};

#define snd_pcm_substream_chip(substream) ((substream)->private_data)
#define snd_pcm_chip(pcm) ((pcm)->private_data)
/* Streams are never linked: each is its own group. */
#define snd_pcm_group_for_each_entry(s, substream) for ((s) = (substream); (s); (s) = NULL)
static inline void snd_pcm_trigger_done(struct snd_pcm_substream *substream, struct snd_pcm_substream *master)
{
	(void)substream; (void)master;
}
static inline void snd_pcm_set_sync(struct snd_pcm_substream *substream) { (void)substream; }

static inline ssize_t frames_to_bytes(struct snd_pcm_runtime *runtime, snd_pcm_sframes_t size)
{
	return size * runtime->frame_bits / 8;
}
static inline snd_pcm_sframes_t bytes_to_frames(struct snd_pcm_runtime *runtime, ssize_t size)
{
	return size * 8 / runtime->frame_bits;
}
static inline size_t snd_pcm_lib_buffer_bytes(struct snd_pcm_substream *substream)
{
	return frames_to_bytes(substream->runtime, substream->runtime->buffer_size);
}
static inline size_t snd_pcm_lib_period_bytes(struct snd_pcm_substream *substream)
{
	return frames_to_bytes(substream->runtime, substream->runtime->period_size);
}
int snd_pcm_format_width(snd_pcm_format_t format);
int snd_pcm_format_physical_width(snd_pcm_format_t format);

int snd_pcm_new(struct snd_card *card, const char *id, int device, int playback_count, int capture_count,
		struct snd_pcm **rpcm);
void snd_pcm_set_ops(struct snd_pcm *pcm, int direction, const struct snd_pcm_ops *ops);
void snd_pcm_set_managed_buffer_all(struct snd_pcm *pcm, int type, struct device *data, size_t size, size_t max);
int snd_pcm_hw_constraint_list(struct snd_pcm_runtime *runtime, unsigned int cond, int var,
			       const struct snd_pcm_hw_constraint_list *l);
int snd_pcm_hw_constraint_ratnums(struct snd_pcm_runtime *runtime, unsigned int cond, int var,
				  const struct snd_pcm_hw_constraint_ratnums *r);
int snd_pcm_hw_constraint_ratdens(struct snd_pcm_runtime *runtime, unsigned int cond, int var,
				  const struct snd_pcm_hw_constraint_ratdens *r);
void snd_pcm_period_elapsed(struct snd_pcm_substream *substream);

/* Channel maps: kept for nobody to read. */
#define SNDRV_CHMAP_UNKNOWN 0
#define SNDRV_CHMAP_NA 1
#define SNDRV_CHMAP_MONO 2
#define SNDRV_CHMAP_FL 3
#define SNDRV_CHMAP_FR 4
#define SNDRV_CHMAP_RL 5
#define SNDRV_CHMAP_RR 6
#define SNDRV_CHMAP_FC 7
#define SNDRV_CHMAP_LFE 8
#define SNDRV_CHMAP_SL 9
#define SNDRV_CHMAP_SR 10
#define SNDRV_CHMAP_RC 11
struct snd_pcm_chmap_elem {
	unsigned char channels;
	unsigned char map[15];
};
struct snd_pcm_chmap;
extern const struct snd_pcm_chmap_elem snd_pcm_std_chmaps[];
extern const struct snd_pcm_chmap_elem snd_pcm_alt_chmaps[];
int snd_pcm_add_chmap_ctls(struct snd_pcm *pcm, int stream, const struct snd_pcm_chmap_elem *chmap,
			   int max_channels, unsigned long private_value, struct snd_pcm_chmap **info_ret);

/* ---- raw MIDI (rawmidi.h): ports with nothing behind them */

#define SNDRV_RAWMIDI_STREAM_OUTPUT 0
#define SNDRV_RAWMIDI_STREAM_INPUT 1
#define SNDRV_RAWMIDI_INFO_OUTPUT 0x00000001
#define SNDRV_RAWMIDI_INFO_INPUT 0x00000002
#define SNDRV_RAWMIDI_INFO_DUPLEX 0x00000004
struct snd_rawmidi_substream {
	struct snd_rawmidi *rmidi;
	int stream;
};
struct snd_rawmidi_ops {
	int (*open)(struct snd_rawmidi_substream *substream);
	int (*close)(struct snd_rawmidi_substream *substream);
	void (*trigger)(struct snd_rawmidi_substream *substream, int up);
	void (*drain)(struct snd_rawmidi_substream *substream);
};
struct snd_rawmidi {
	struct snd_card *card;
	int device;
	char id[64];
	char name[80];
	unsigned int info_flags;
	void *private_data;
	void (*private_free)(struct snd_rawmidi *rmidi);
	const struct snd_rawmidi_ops *lde_ops[2];
	struct snd_rawmidi *lde_next;
};
int snd_rawmidi_new(struct snd_card *card, char *id, int device, int output_count, int input_count,
		    struct snd_rawmidi **rmidi);
void snd_rawmidi_set_ops(struct snd_rawmidi *rmidi, int stream, const struct snd_rawmidi_ops *ops);
int snd_rawmidi_receive(struct snd_rawmidi_substream *substream, const unsigned char *buffer, int count);
int snd_rawmidi_transmit(struct snd_rawmidi_substream *substream, unsigned char *buffer, int count);

/* ---- the AK4531 codec (ak4531_codec.h): Linux's ak4531_codec.c is
 * compiled with the driver that needs it. Register numbers are the
 * chip's. */

#define AK4531_LMASTER 0x00
#define AK4531_RMASTER 0x01
#define AK4531_LVOICE 0x02
#define AK4531_RVOICE 0x03
#define AK4531_LFM 0x04
#define AK4531_RFM 0x05
#define AK4531_LCD 0x06
#define AK4531_RCD 0x07
#define AK4531_LLINE 0x08
#define AK4531_RLINE 0x09
#define AK4531_LAUXA 0x0a
#define AK4531_RAUXA 0x0b
#define AK4531_MONO1 0x0c
#define AK4531_MONO2 0x0d
#define AK4531_MIC 0x0e
#define AK4531_MONO_OUT 0x0f
#define AK4531_OUT_SW1 0x10
#define AK4531_OUT_SW2 0x11
#define AK4531_LIN_SW1 0x12
#define AK4531_RIN_SW1 0x13
#define AK4531_LIN_SW2 0x14
#define AK4531_RIN_SW2 0x15
#define AK4531_RESET 0x16
#define AK4531_CLOCK 0x17
#define AK4531_AD_IN 0x18
#define AK4531_MIC_GAIN 0x19
struct snd_ak4531 {
	void (*write)(struct snd_ak4531 *ak4531, unsigned short reg, unsigned short val);
	void *private_data;
	void (*private_free)(struct snd_ak4531 *ak4531);
	unsigned char regs[0x20];
	struct mutex reg_mutex;
};
int snd_ak4531_mixer(struct snd_card *card, struct snd_ak4531 *_ak4531, struct snd_ak4531 **rak4531);

#endif
