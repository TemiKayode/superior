// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * The Linux Driver Environment's sound (lde/sound.h): the ALSA core under
 * a hosted PCI sound driver, and the calls its Rust host
 * (crates/lde/src/sound.rs) makes to play through it. Written for
 * Superior; nothing here is Linux's.
 *
 * The driver makes one card. The host opens one playback stream at a
 * time, as ALSA's userspace would: it opens the substream (the driver's
 * open says what the hardware takes), checks its format, rate, buffer and
 * period against that, gives the driver the buffer, prepares and starts
 * it; then reads the hardware's position and counts the periods the
 * driver's interrupt reports.
 */
#include <lde/host.h>
#include <lde/sound.h>

static struct snd_card *card;

/* ---- the card */

int snd_devm_card_new(struct device *parent, int idx, const char *xid, struct module *module,
		      size_t extra_size, struct snd_card **card_ret)
{
	(void)idx;
	(void)module;
	*card_ret = NULL;
	if (card)
		return -EBUSY;
	/* The driver's own part follows the card, aligned as kmalloc's are. */
	size_t head = ALIGN(sizeof(struct snd_card), 64);
	struct snd_card *c = kzalloc(head + extra_size, GFP_KERNEL);
	if (!c)
		return -ENOMEM;
	c->dev = parent;
	c->private_data = extra_size ? (char *)c + head : NULL;
	strscpy(c->id, xid ? xid : "card0", sizeof(c->id));
	card = c;
	*card_ret = c;
	return 0;
}

static void free_card(struct snd_card *c)
{
	if (c->private_free)
		c->private_free(c);
	for (struct snd_device *d = c->lde_devices; d; d = d->lde_next)
		if (d->ops && d->ops->dev_free)
			d->ops->dev_free(d);
	/* The rest is the component's memory, which goes with it. */
	if (card == c)
		card = NULL;
}

int snd_card_free_on_error(struct device *dev, int ret)
{
	(void)dev;
	if (ret < 0 && card)
		free_card(card);
	return ret;
}

int snd_card_register(struct snd_card *c)
{
	for (struct snd_device *d = c->lde_devices; d; d = d->lde_next)
		if (d->ops && d->ops->dev_register) {
			int err = d->ops->dev_register(d);
			if (err < 0)
				return err;
		}
	c->lde_registered = true;
	return 0;
}

int snd_component_add(struct snd_card *c, const char *component)
{
	size_t have = strlen(c->components), add = strlen(component);
	if (have + add + 2 > sizeof(c->components))
		return -ENOMEM;
	if (have)
		c->components[have++] = ' ';
	memcpy(c->components + have, component, add + 1);
	return 0;
}

int snd_device_new(struct snd_card *c, enum snd_device_type type, void *device_data,
		   const struct snd_device_ops *ops)
{
	struct snd_device *d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return -ENOMEM;
	d->card = c;
	d->type = type;
	d->device_data = device_data;
	d->ops = ops;
	d->lde_next = c->lde_devices;
	c->lde_devices = d;
	return 0;
}

struct snd_dma_buffer *snd_devm_alloc_pages(struct device *dev, int type, size_t size)
{
	struct snd_dma_buffer *b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return NULL;
	b->area = dma_alloc_coherent(dev, size, &b->addr, GFP_KERNEL);
	if (!b->area) {
		kfree(b);
		return NULL;
	}
	b->dev.type = type;
	b->dev.dev = dev;
	b->bytes = size;
	return b;
}

/* ---- controls */

struct snd_kcontrol *snd_ctl_new1(const struct snd_kcontrol_new *n, void *private_data)
{
	struct snd_kcontrol *k = kzalloc(sizeof(*k), GFP_KERNEL);
	if (!k)
		return NULL;
	k->id.iface = n->iface;
	k->id.device = n->device;
	k->id.subdevice = n->subdevice;
	k->id.index = n->index;
	if (n->name)
		strscpy(k->id.name, n->name, sizeof(k->id.name));
	k->count = n->count ? n->count : 1;
	k->access = n->access ? n->access : SNDRV_CTL_ELEM_ACCESS_READWRITE;
	k->info = n->info;
	k->get = n->get;
	k->put = n->put;
	k->tlv.p = n->tlv.p;
	k->private_value = n->private_value;
	k->private_data = private_data;
	return k;
}

int snd_ctl_add(struct snd_card *c, struct snd_kcontrol *k)
{
	if (!k)
		return -ENOMEM;
	/* Kept in the order added. */
	struct snd_kcontrol **at = &c->lde_controls;
	unsigned int numid = 1;
	for (; *at; at = &(*at)->lde_next)
		numid++;
	k->id.numid = numid;
	*at = k;
	return 0;
}

int snd_ctl_boolean_mono_info(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_info *uinfo)
{
	(void)kcontrol;
	uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
	uinfo->count = 1;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 1;
	return 0;
}

int snd_ctl_boolean_stereo_info(struct snd_kcontrol *kcontrol, struct snd_ctl_elem_info *uinfo)
{
	snd_ctl_boolean_mono_info(kcontrol, uinfo);
	uinfo->count = 2;
	return 0;
}

/* ---- PCM devices */

int snd_pcm_new(struct snd_card *c, const char *id, int device, int playback_count, int capture_count,
		struct snd_pcm **rpcm)
{
	if (rpcm)
		*rpcm = NULL;
	if (playback_count > LDE_SND_SUBSTREAMS || capture_count > LDE_SND_SUBSTREAMS)
		return -EINVAL;
	struct snd_pcm *pcm = kzalloc(sizeof(*pcm), GFP_KERNEL);
	if (!pcm)
		return -ENOMEM;
	pcm->card = c;
	pcm->device = device;
	if (id)
		strscpy(pcm->id, id, sizeof(pcm->id));
	pcm->lde_count[SNDRV_PCM_STREAM_PLAYBACK] = playback_count;
	pcm->lde_count[SNDRV_PCM_STREAM_CAPTURE] = capture_count;
	for (int dir = 0; dir < 2; dir++)
		for (int i = 0; i < LDE_SND_SUBSTREAMS; i++) {
			struct snd_pcm_substream *s = &pcm->lde_sub[dir][i];
			s->pcm = pcm;
			s->stream = dir;
			s->number = i;
			snprintf(s->name, sizeof(s->name), "subdevice #%d", i);
		}
	struct snd_pcm **at = &c->lde_pcms;
	while (*at)
		at = &(*at)->lde_next;
	*at = pcm;
	if (rpcm)
		*rpcm = pcm;
	return 0;
}

void snd_pcm_set_ops(struct snd_pcm *pcm, int direction, const struct snd_pcm_ops *ops)
{
	for (int i = 0; i < LDE_SND_SUBSTREAMS; i++)
		pcm->lde_sub[direction][i].ops = ops;
}

void snd_pcm_set_managed_buffer_all(struct snd_pcm *pcm, int type, struct device *data, size_t size, size_t max)
{
	(void)type;
	(void)data;
	for (int dir = 0; dir < 2; dir++)
		for (int i = 0; i < LDE_SND_SUBSTREAMS; i++) {
			pcm->lde_sub[dir][i].lde_buffer_size = size;
			pcm->lde_sub[dir][i].lde_buffer_max = max;
		}
}

static int add_constraint(struct snd_pcm_runtime *runtime, int var, int kind, const void *what)
{
	if (var != SNDRV_PCM_HW_PARAM_RATE || runtime->lde_constraints == LDE_SND_CONSTRAINTS)
		return -EINVAL;
	runtime->lde_rates[runtime->lde_constraints].kind = kind;
	runtime->lde_rates[runtime->lde_constraints].what = what;
	runtime->lde_constraints++;
	return 0;
}

int snd_pcm_hw_constraint_list(struct snd_pcm_runtime *runtime, unsigned int cond, int var,
			       const struct snd_pcm_hw_constraint_list *l)
{
	(void)cond;
	return add_constraint(runtime, var, 1, l);
}

int snd_pcm_hw_constraint_ratnums(struct snd_pcm_runtime *runtime, unsigned int cond, int var,
				  const struct snd_pcm_hw_constraint_ratnums *r)
{
	(void)cond;
	return add_constraint(runtime, var, 2, r);
}

int snd_pcm_hw_constraint_ratdens(struct snd_pcm_runtime *runtime, unsigned int cond, int var,
				  const struct snd_pcm_hw_constraint_ratdens *r)
{
	(void)cond;
	return add_constraint(runtime, var, 3, r);
}

void snd_pcm_period_elapsed(struct snd_pcm_substream *substream)
{
	substream->lde_periods++;
}

int snd_pcm_format_width(snd_pcm_format_t format)
{
	switch (format) {
	case SNDRV_PCM_FORMAT_S8:
	case SNDRV_PCM_FORMAT_U8:
		return 8;
	case SNDRV_PCM_FORMAT_S16_LE:
	case SNDRV_PCM_FORMAT_S16_BE:
	case SNDRV_PCM_FORMAT_U16_LE:
	case SNDRV_PCM_FORMAT_U16_BE:
		return 16;
	case SNDRV_PCM_FORMAT_S32_LE:
		return 32;
	default:
		return -EINVAL;
	}
}

int snd_pcm_format_physical_width(snd_pcm_format_t format)
{
	return snd_pcm_format_width(format);
}

const struct snd_pcm_chmap_elem snd_pcm_std_chmaps[] = {
	{ .channels = 1, .map = { SNDRV_CHMAP_MONO } },
	{ .channels = 2, .map = { SNDRV_CHMAP_FL, SNDRV_CHMAP_FR } },
	{ .channels = 4, .map = { SNDRV_CHMAP_FL, SNDRV_CHMAP_FR, SNDRV_CHMAP_RL, SNDRV_CHMAP_RR } },
	{}
};

const struct snd_pcm_chmap_elem snd_pcm_alt_chmaps[] = {
	{ .channels = 1, .map = { SNDRV_CHMAP_MONO } },
	{ .channels = 2, .map = { SNDRV_CHMAP_FL, SNDRV_CHMAP_FR } },
	{ .channels = 4, .map = { SNDRV_CHMAP_FL, SNDRV_CHMAP_FR, SNDRV_CHMAP_RL, SNDRV_CHMAP_RR } },
	{}
};

int snd_pcm_add_chmap_ctls(struct snd_pcm *pcm, int stream, const struct snd_pcm_chmap_elem *chmap,
			   int max_channels, unsigned long private_value, struct snd_pcm_chmap **info_ret)
{
	(void)pcm; (void)stream; (void)chmap; (void)max_channels; (void)private_value;
	if (info_ret)
		*info_ret = NULL;
	return 0;
}

/* ---- raw MIDI: the ports are made; nothing opens them */

int snd_rawmidi_new(struct snd_card *c, char *id, int device, int output_count, int input_count,
		    struct snd_rawmidi **rrawmidi)
{
	(void)output_count;
	(void)input_count;
	struct snd_rawmidi *r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (rrawmidi)
		*rrawmidi = r;
	if (!r)
		return -ENOMEM;
	r->card = c;
	r->device = device;
	if (id)
		strscpy(r->id, id, sizeof(r->id));
	r->lde_next = c->lde_midis;
	c->lde_midis = r;
	return 0;
}

void snd_rawmidi_set_ops(struct snd_rawmidi *rmidi, int stream, const struct snd_rawmidi_ops *ops)
{
	rmidi->lde_ops[stream] = ops;
}

int snd_rawmidi_receive(struct snd_rawmidi_substream *substream, const unsigned char *buffer, int count)
{
	(void)substream; (void)buffer;
	return count;
}

int snd_rawmidi_transmit(struct snd_rawmidi_substream *substream, unsigned char *buffer, int count)
{
	(void)substream; (void)buffer; (void)count;
	return 0;
}

/* ---- the host's calls */

/* The playback stream the host has open, if any. */
static struct snd_pcm_substream *playing;

/* The card's long name, its PCM devices, MIDI ports and controls. */
const char *lde_snd_card(unsigned int *pcms, unsigned int *midis, unsigned int *controls)
{
	*pcms = *midis = *controls = 0;
	if (!card || !card->lde_registered)
		return NULL;
	for (struct snd_pcm *p = card->lde_pcms; p; p = p->lde_next)
		(*pcms)++;
	for (struct snd_rawmidi *r = card->lde_midis; r; r = r->lde_next)
		(*midis)++;
	for (struct snd_kcontrol *k = card->lde_controls; k; k = k->lde_next)
		(*controls)++;
	return card->longname;
}

/* PCM device `i`'s name and how many playback substreams it has. */
const char *lde_snd_pcm(unsigned int i, int *device, unsigned int *playback)
{
	struct snd_pcm *p = card ? card->lde_pcms : NULL;
	for (; p && i; i--)
		p = p->lde_next;
	if (!p)
		return NULL;
	*device = p->device;
	*playback = p->lde_count[SNDRV_PCM_STREAM_PLAYBACK];
	return p->name;
}

/* Sets every channel of mixer control `name` (index 0) to its largest
 * value: a switch on, a volume full. 1 if it changed, 0 if it was so
 * already, -errno if there is no such control. */
int lde_snd_control_max(const char *name)
{
	for (struct snd_kcontrol *k = card ? card->lde_controls : NULL; k; k = k->lde_next) {
		if (k->id.index || strcmp(k->id.name, name) || !k->info || !k->put)
			continue;
		struct snd_ctl_elem_info info;
		memset(&info, 0, sizeof(info));
		info.id = k->id;
		int err = k->info(k, &info);
		if (err < 0)
			return err;
		if (info.type != SNDRV_CTL_ELEM_TYPE_BOOLEAN && info.type != SNDRV_CTL_ELEM_TYPE_INTEGER)
			return -EINVAL;
		/* The value is large: not on the host's small stack. */
		static struct snd_ctl_elem_value value;
		memset(&value, 0, sizeof(value));
		value.id = k->id;
		for (unsigned int c = 0; c < info.count && c < 128; c++)
			value.value.integer.value[c] = info.value.integer.max;
		return k->put(k, &value);
	}
	return -ENOENT;
}

static bool rate_in(const struct lde_snd_constraint *c, unsigned int rate)
{
	switch (c->kind) {
	case 1: {
		const struct snd_pcm_hw_constraint_list *l = c->what;
		for (unsigned int i = 0; i < l->count; i++)
			if ((!l->mask || l->mask & (1u << i)) && l->list[i] == rate)
				return true;
		return false;
	}
	case 2: {
		/* rate = num / den for a den in the range. */
		const struct snd_pcm_hw_constraint_ratnums *r = c->what;
		for (int i = 0; i < r->nrats; i++) {
			const struct snd_ratnum *n = &r->rats[i];
			if (n->num % rate)
				continue;
			unsigned int den = n->num / rate;
			if (den >= n->den_min && den <= n->den_max && (den - n->den_min) % n->den_step == 0)
				return true;
		}
		return false;
	}
	case 3: {
		/* rate = num / den for a num in the range. */
		const struct snd_pcm_hw_constraint_ratdens *r = c->what;
		for (int i = 0; i < r->nrats; i++) {
			const struct snd_ratden *d = &r->rats[i];
			u64 num = (u64)rate * d->den;
			if (num >= d->num_min && num <= d->num_max && (num - d->num_min) % d->num_step == 0)
				return true;
		}
		return false;
	}
	}
	return false;
}

/* The bit of a standard rate in snd_pcm_hardware's `rates`; 0 if it is
 * not one. */
static unsigned int rate_bit(unsigned int rate)
{
	static const unsigned int standard[] = { 5512, 8000, 11025, 16000, 22050, 32000, 44100,
						  48000, 64000, 88200, 96000, 176400, 192000 };
	for (unsigned int i = 0; i < ARRAY_SIZE(standard); i++)
		if (standard[i] == rate)
			return 1u << i;
	return 0;
}

static void close_substream(struct snd_pcm_substream *s)
{
	if (s->ops->close)
		s->ops->close(s);
	if (s->runtime) {
		if (s->runtime->dma_area)
			lde_host_free(s->runtime->dma_area);
		kfree(s->runtime);
		s->runtime = NULL;
	}
}

/* Closes the stream the host has open, stopping it first. */
void lde_snd_close(void)
{
	struct snd_pcm_substream *s = playing;
	if (!s)
		return;
	playing = NULL;
	s->ops->trigger(s, SNDRV_PCM_TRIGGER_STOP);
	if (s->ops->hw_free)
		s->ops->hw_free(s);
	close_substream(s);
}

/* Opens the first playback substream of PCM device `device` for signed
 * 16-bit little-endian frames of `channels` at `rate`, with a buffer of
 * `buffer` bytes in periods of `period` bytes, and prepares it. Its
 * buffer and the device's address for it come back. 0 or -errno; what the
 * hardware would not take is logged. */
int lde_snd_open(int device, unsigned int rate, unsigned int channels, unsigned int buffer,
		 unsigned int period, void **area, u64 *dma)
{
	lde_snd_close();
	struct snd_pcm *p = card ? card->lde_pcms : NULL;
	while (p && p->device != device)
		p = p->lde_next;
	if (!p || !p->lde_count[SNDRV_PCM_STREAM_PLAYBACK])
		return -ENODEV;
	struct snd_pcm_substream *s = &p->lde_sub[SNDRV_PCM_STREAM_PLAYBACK][0];
	if (!s->ops || !s->ops->open || !s->ops->prepare || !s->ops->trigger || !s->ops->pointer)
		return -ENODEV;
	struct snd_pcm_runtime *r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;
	s->runtime = r;
	s->private_data = p->private_data;
	s->lde_periods = 0;
	int err = s->ops->open(s);
	if (err < 0) {
		kfree(r);
		s->runtime = NULL;
		return err;
	}
	/* What the hardware takes, as the driver's open said. */
	const struct snd_pcm_hardware *hw = &r->hw;
	const char *refused = NULL;
	if (!(hw->formats & SNDRV_PCM_FMTBIT_S16_LE) || !(hw->info & SNDRV_PCM_INFO_INTERLEAVED))
		refused = "interleaved signed 16-bit frames";
	else if (channels < hw->channels_min || channels > hw->channels_max)
		refused = "the channels";
	else if (rate < hw->rate_min || rate > hw->rate_max ||
		 !(hw->rates & (SNDRV_PCM_RATE_CONTINUOUS | SNDRV_PCM_RATE_KNOT) || hw->rates & rate_bit(rate)))
		refused = "the rate";
	else if (buffer > hw->buffer_bytes_max || buffer > s->lde_buffer_max || period < hw->period_bytes_min ||
		 period > hw->period_bytes_max || buffer % period || buffer / period < hw->periods_min ||
		 buffer / period > hw->periods_max)
		refused = "the buffer or period";
	for (unsigned int i = 0; !refused && i < r->lde_constraints; i++)
		if (!rate_in(&r->lde_rates[i], rate))
			refused = "the rate";
	if (refused) {
		_printk("sound: %s takes not %s (%u Hz, %u channels, %u-byte buffer, %u-byte periods)\n",
			p->name, refused, rate, channels, buffer, period);
		close_substream(s);
		return -EINVAL;
	}
	r->format = SNDRV_PCM_FORMAT_S16_LE;
	r->rate = rate;
	r->channels = channels;
	r->sample_bits = 16;
	r->frame_bits = 16 * channels;
	r->buffer_size = buffer / (2 * channels);
	r->period_size = period / (2 * channels);
	r->periods = buffer / period;
	/* The managed buffer: contiguous for the device. */
	r->dma_area = lde_host_alloc(buffer);
	r->dma_addr = r->dma_area ? lde_host_dma(r->dma_area, buffer) : DMA_MAPPING_ERROR;
	if (r->dma_addr == DMA_MAPPING_ERROR) {
		_printk("sound: no %u bytes in a row for the device\n", buffer);
		close_substream(s);
		return -ENOMEM;
	}
	r->dma_bytes = buffer;
	err = s->ops->prepare(s);
	if (err < 0) {
		close_substream(s);
		return err;
	}
	playing = s;
	*area = r->dma_area;
	*dma = r->dma_addr;
	return 0;
}

/* Starts (or stops) the open stream. 0 or -errno. */
int lde_snd_trigger(int start)
{
	if (!playing)
		return -EINVAL;
	return playing->ops->trigger(playing, start ? SNDRV_PCM_TRIGGER_START : SNDRV_PCM_TRIGGER_STOP);
}

/* Where the hardware is in the open stream's buffer, in frames. */
unsigned long lde_snd_pointer(void)
{
	return playing ? playing->ops->pointer(playing) : 0;
}

/* Periods the driver's interrupt has reported for the open stream. */
unsigned long lde_snd_periods(void)
{
	return playing ? playing->lde_periods : 0;
}
