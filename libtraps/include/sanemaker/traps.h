#ifndef SANEMAKER_TRAPS_H
#define SANEMAKER_TRAPS_H

/* Define trap API attributes */

#define SANEMAKER_TRAP_API extern __attribute__((visibility("default")))

/* Use sanemaker_target_tag(&obj) to make sanemaker watch memops to that object */

#ifdef SANEMAKER

SANEMAKER_TRAP_API
void __sanemaker_target_tag_trap(const void *ptr, const unsigned char *target);

#define sanemaker_target_tag(ptr, type) \
	__sanemaker_target_tag_trap(ptr, spslr_target_hash(type))

#else

#define sanemaker_target_tag(ptr, type)

#endif

/* Use sanemaker_target_untag(&obj) to make sanemaker stop watching memops to that object */

#ifdef SANEMAKER

SANEMAKER_TRAP_API
void __sanemaker_target_untag_trap(const void *ptr);

#define sanemaker_target_untag(ptr) __sanemaker_target_untag_trap(ptr)

#else

#define sanemaker_target_untag(ptr)

#endif

/* The sanemaker_finish_layout(&fieldarr, &target_hash) should be called
   by spslr selfpatch when a target layout has been randomized */

#ifdef SANEMAKER

SANEMAKER_TRAP_API
void __sanemaker_finish_layout_trap(const void *fields,
				    const unsigned char *target);

#define sanemaker_finish_layout(fields, target) \
	__sanemaker_finish_layout_trap(fields, target)

#else

#define sanemaker_finish_layout(fields, target)

#endif

/* Use sanemaker_fetch(what, default) to let sanemaker make decisions at runtime */

typedef enum {
	SANEMAKER_FETCH_SPSLR_ENABLED = 1,
} sanemaker_fetch_t;

#ifdef SANEMAKER

SANEMAKER_TRAP_API
int __sanemaker_fetch_trap(sanemaker_fetch_t what, int def);

#define sanemaker_fetch(what, def) __sanemaker_fetch_trap(what, def)

#else

#define sanemaker_fetch(what, def) (def)

#endif

/* Use sanemaker_signal(signal) to control sanemaker behavior */

typedef enum {
	SANEMAKER_SIGNAL_PATCH_BOUNDARY = 1, /* the image has been patched */
	SANEMAKER_SIGNAL_PAUSE = 2,
	SANEMAKER_SIGNAL_RESUME = 3,
} sanemaker_signal_t;

#ifdef SANEMAKER

SANEMAKER_TRAP_API
void __sanemaker_signal_trap(sanemaker_signal_t signal);

#define sanemaker_signal(signal) __sanemaker_signal_trap(signal)

#else

#define sanemaker_signal(signal)

#endif

/* Use sanemaker_new_image(name, ptr) and sanemaker_new_image_text(image, begin, end)
   to allow normalization of program counters inside dynamically loaded text segments */

#ifdef SANEMAKER

SANEMAKER_TRAP_API
void __sanemaker_new_image_trap(const char *name, const void *base);

SANEMAKER_TRAP_API
void __sanemaker_new_image_text_trap(const char *image, const void *begin,
				     const void *end);

SANEMAKER_TRAP_API
void __sanemaker_drop_image_trap(const char *image);

SANEMAKER_TRAP_API
void __sanemaker_drop_image_text_trap(const char *image, const void *begin,
				      const void *end);

#define sanemaker_new_image(name, base) __sanemaker_new_image_trap(name, base)

#define sanemaker_new_image_text(image, begin, end) \
	__sanemaker_new_image_text_trap(image, begin, end)

#define sanemaker_drop_image(image) __sanemaker_drop_image_trap(image)

#define sanemaker_drop_image_text(image, begin, end) \
	__sanemaker_drop_image_text_trap(image, begin, end)

#else

#define sanemaker_new_image(name, base)
#define sanemaker_new_image_text(image, begin, end)
#define sanemaker_drop_image(image)
#define sanemaker_drop_image_text(image, begin, end)

#endif

#endif
