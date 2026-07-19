#include <sanemaker/traps.h>

#define SANEMAKER_TRAP_FN                                           \
	__attribute__((noinline, noclone, used, externally_visible, \
		       visibility("default"), naked))

/* Sanemaker reads object pointer from rdi and target hash pointer from rsi */
SANEMAKER_TRAP_FN
void __sanemaker_target_tag_trap(const void *ptr, const unsigned char *target)
{
	__asm__ volatile(".globl __sanemaker_target_tag_trap_incision\n"
			 ".type __sanemaker_target_tag_trap_incision, @notype\n"
			 "__sanemaker_target_tag_trap_incision:\n"
			 "ret\n");
}

/* Sanemaker reads object pointer from rdi */
SANEMAKER_TRAP_FN
void __sanemaker_target_untag_trap(const void *ptr)
{
	__asm__ volatile(
		".globl __sanemaker_target_untag_trap_incision\n"
		".type __sanemaker_target_untag_trap_incision, @notype\n"
		"__sanemaker_target_untag_trap_incision:\n"
		"ret\n");
}

/* Sanemaker reads field pointer from rdi and target hash pointer from rsi */
SANEMAKER_TRAP_FN
void __sanemaker_finish_layout_trap(const void *fields,
				    const unsigned char *target)
{
	__asm__ volatile(
		".globl __sanemaker_finish_layout_trap_incision\n"
		".type __sanemaker_finish_layout_trap_incision, @notype\n"
		"__sanemaker_finish_layout_trap_incision:\n"
		"ret\n");
}

/* Sanemaker reads name from rdi and overwrites rsi to set a value */
SANEMAKER_TRAP_FN
int __sanemaker_fetch_trap(sanemaker_fetch_t what, int def)
{
	__asm__ volatile(".globl __sanemaker_fetch_trap_incision\n"
			 ".type __sanemaker_fetch_trap_incision, @notype\n"
			 "__sanemaker_fetch_trap_incision:\n"
			 "nop\n"
			 "movl %esi, %eax\n"
			 "ret\n");
}

/* Sanemaker reads the signal event from rdi */
SANEMAKER_TRAP_FN
void __sanemaker_signal_trap(sanemaker_signal_t signal)
{
	__asm__ volatile(".globl __sanemaker_signal_trap_incision\n"
			 ".type __sanemaker_signal_trap_incision, @notype\n"
			 "__sanemaker_signal_trap_incision:\n"
			 "ret\n");
}

/* Sanemaker reads name from rdi and base from rsi */
SANEMAKER_TRAP_FN
void __sanemaker_new_image_trap(const char *name, const void *base)
{
	__asm__ volatile(".globl __sanemaker_new_image_trap_incision\n"
			 ".type __sanemaker_new_image_trap_incision, @notype\n"
			 "__sanemaker_new_image_trap_incision:\n"
			 "ret\n");
}

/* Sanemaker reads image name from rdi, begin from rsi and end from rdx */
SANEMAKER_TRAP_FN
void __sanemaker_new_image_text_trap(const char *image, const void *begin,
				     const void *end)
{
	__asm__ volatile(
		".globl __sanemaker_new_image_text_trap_incision\n"
		".type __sanemaker_new_image_text_trap_incision, @notype\n"
		"__sanemaker_new_image_text_trap_incision:\n"
		"ret\n");
}

/* Sanemaker reads image name from rdi */
SANEMAKER_TRAP_FN
void __sanemaker_drop_image_trap(const char *image)
{
	__asm__ volatile(".globl __sanemaker_drop_image_trap_incision\n"
			 ".type __sanemaker_drop_image_trap_incision, @notype\n"
			 "__sanemaker_drop_image_trap_incision:\n"
			 "ret\n");
}

/* Sanemaker reads image name from rdi, begin from rsi and end from rdx */
SANEMAKER_TRAP_FN
void __sanemaker_drop_image_text_trap(const char *image, const void *begin,
				      const void *end)
{
	__asm__ volatile(
		".globl __sanemaker_drop_image_text_trap_incision\n"
		".type __sanemaker_drop_image_text_trap_incision, @notype\n"
		"__sanemaker_drop_image_text_trap_incision:\n"
		"ret\n");
}
