/* Lab 11 — requested vs. observed enforcement, measured on a CET shadow stack.
 *
 * One operation: a function returns through a saved return address that an
 * in-binary overflow has overwritten with the address of hijack(). This is the
 * exact operation an Intel CET shadow stack is meant to stop: on RET the CPU
 * compares the return address on the ordinary stack with the shadow copy and
 * raises a control-protection fault on a mismatch.
 *
 * The overflow is entirely in-binary and deterministic: main() builds a fixed
 * payload (filler bytes, then &hijack at the saved-return-address offset) and
 * passes it to victim(), which copies it into a short buffer. No external input
 * and no information disclosure; &hijack is the program's own symbol. Labs 05,
 * 06 and 08 use the same controlled-overflow style for their own targets.
 *
 * The point of the lab is NOT that the overflow works — it is that whether the
 * shadow stack STOPS it depends on runtime activation, not on the build flag or
 * the ELF metadata. Two measurements are therefore made INSIDE this very process,
 * so the activation state and the fault cause cannot be mis-attributed from a
 * different process:
 *
 *   1. Before the overflow, the program reads its OWN shadow-stack status with
 *      arch_prctl(ARCH_SHSTK_STATUS) and prints it as "SHSTK_STATUS=0x..." on
 *      stderr. This is the per-process "activated" link, not a separate probe's.
 *   2. A SA_SIGINFO SIGSEGV handler prints the siginfo si_code as "SEGV_SI_CODE=..".
 *      A shadow-stack RET mismatch is reported by Linux as SEGV_CPERR (a control-
 *      protection fault), distinct from an ordinary mapping/access fault. This is
 *      the positive mechanism evidence: a block is only attributed to the shadow
 *      stack when the fault is SEGV_CPERR, never for an arbitrary SIGSEGV.
 *
 * The offset 24 = 16 (buffer) + 8 (saved rbp) places &hijack on the saved return
 * address for this -O0 -fno-stack-protector -no-pie layout; the collector asserts
 * the layout by checking the unprotected reference actually reaches hijack.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>

#define BUF_LEN 16
#define SAVED_RET_OFFSET 24      /* buffer (16) + saved frame pointer (8) */
#define PAYLOAD_LEN 32
#define HIJACK_STATUS 42
#define SEGV_FAULT_STATUS 70     /* exit code the fault handler uses */

/* arch_prctl shadow-stack status subfunction; define locally so the lab builds on
 * toolchains whose headers predate it. Bit 0 (SHSTK_EN) means the shadow stack is
 * active for this thread. Kernel: Documentation/x86/shstk.rst. */
#ifndef ARCH_SHSTK_STATUS
#define ARCH_SHSTK_STATUS 0x5005
#endif
/* si_code for a control-protection fault (shadow-stack / IBT violation). Added in
 * Linux uapi as SEGV_CPERR; define locally for older headers. */
#ifndef SEGV_CPERR
#define SEGV_CPERR 10
#endif

/* The control-flow target the overwrite redirects to. Never called directly. */
static void hijack(void)
{
	printf("HIJACK: control-flow redirected\n");
	fflush(stdout);
	_exit(HIJACK_STATUS);
}

/* Append the decimal form of a small non-negative int to buf at *pos. Used only
 * from the signal handler, so it touches no library state. */
static void append_int(char *buf, size_t *pos, size_t cap, int value)
{
	char digits[16];
	size_t n = 0;
	unsigned int v = value < 0 ? (unsigned int)(-(long)value) : (unsigned int)value;
	if (value < 0 && *pos < cap)
		buf[(*pos)++] = '-';
	do {
		digits[n++] = (char)('0' + (v % 10));
		v /= 10;
	} while (v && n < sizeof digits);
	while (n && *pos < cap)
		buf[(*pos)++] = digits[--n];
}

/* Report the fault's si_code so the collector can require SEGV_CPERR before
 * attributing the stop to the shadow stack. Async-signal-safe: builds the line in
 * a local buffer and emits it with a single write(2); no stdio, no malloc. See
 * signal-safety(7) — write() is on the safe list, dprintf()/printf() are not. */
static void on_segv(int sig, siginfo_t *info, void *context)
{
	static const char prefix[] = "SEGV_SI_CODE=";
	static const char cperr[] = " SEGV_CPERR";
	char line[48];
	size_t pos = 0;

	(void)sig;
	(void)context;
	for (size_t i = 0; i < sizeof prefix - 1; i++)
		line[pos++] = prefix[i];
	append_int(line, &pos, sizeof line, info->si_code);
	if (info->si_code == SEGV_CPERR)
		for (size_t i = 0; i < sizeof cperr - 1 && pos < sizeof line; i++)
			line[pos++] = cperr[i];
	if (pos < sizeof line)
		line[pos++] = '\n';
	(void)!write(STDERR_FILENO, line, pos);
	_exit(SEGV_FAULT_STATUS);
}

/* The vulnerable frame: a fixed-size buffer the copy overflows. Marked noinline
 * so the frame and its saved return address exist at -O2 as well as -O0. */
__attribute__((noinline))
static void victim(const uint8_t *src, size_t n)
{
	char buf[BUF_LEN];
	memcpy(buf, src, n);         /* deliberate overflow when n > BUF_LEN */
	printf("victim returned normally\n");
	fflush(stdout);
}

int main(int argc, char **argv)
{
	uint8_t payload[PAYLOAD_LEN];
	uintptr_t target = (uintptr_t)&hijack;
	unsigned long long shstk_status = 0;
	long rc;

	/* (1) Record THIS process's shadow-stack status before doing anything else. */
	rc = syscall(SYS_arch_prctl, ARCH_SHSTK_STATUS, &shstk_status);
	if (rc == 0)
		dprintf(2, "SHSTK_STATUS=0x%llx\n", shstk_status);
	else
		dprintf(2, "SHSTK_STATUS=unavailable\n");

	/* (2) Install the siginfo fault handler so a fault reports its si_code. */
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = on_segv;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSEGV, &sa, NULL) != 0) {
		dprintf(2, "sigaction failed\n");
		return 1;
	}

	/* Build the payload: filler, then the saved-return-address slot = &hijack. */
	memset(payload, 0x41, sizeof payload);
	memcpy(payload + SAVED_RET_OFFSET, &target, sizeof target);

	/* n defaults to a full overwrite; "safe" runs a non-overflowing copy so the
	 * baseline control returns normally. Any explicit length is clamped to the
	 * payload so the program never reads out of its own buffer. */
	size_t n = PAYLOAD_LEN;
	if (argc > 1) {
		long requested = strtol(argv[1], NULL, 10);
		if (requested < 0)
			requested = 0;
		if ((size_t)requested > PAYLOAD_LEN)
			requested = PAYLOAD_LEN;
		n = (size_t)requested;
	}

	victim(payload, n);
	printf("main completed\n");
	return 0;
}
