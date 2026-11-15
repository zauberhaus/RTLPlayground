#include "machine.h"
#include "syslog.h"
#include "cmd_parser.h"
#include "uip/uip.h"
#include "uip/uip_arp.h"
#include "rtl837x_common.h"

#pragma codeseg BANK2
#pragma constseg BANK2

#define SYSLOG_P ((__xdata uint8_t *)uip_appdata)

__xdata char logbuf[LOGBUF_SIZE];
__xdata struct syslog_state syslog_state;
__xdata uip_ipaddr_t server_ip;

#define state syslog_state 

void syslog_init(void) __banked
{
	state.enabled = 0;
	state.syslog_conn = 0;
	state.writeptr = 0;
	state.readptr = 0;
	state.line_available = 0;
	state.server_ip[0] = 0; state.server_ip[1] = 0; state.server_ip[2] = 0; state.server_ip[3] = 0;// Default to 0.0.0.0
	state.server_port = SYSLOG_PORT_DEFAULT;
}

void syslog_start(void) __banked
{
	if (state.syslog_conn == 0) {
		uip_ipaddr(server_ip, state.server_ip[0], state.server_ip[1], state.server_ip[2], state.server_ip[3]);
		state.syslog_conn = uip_udp_new(&server_ip, HTONS(state.server_port));
		if (state.syslog_conn == 0) {
			print_string_newline_no_syslog("Failed to create a new UDP client");
			return;
		}
		print_string_newline_no_syslog("Started syslog to IP ");
		print_ip(state.server_ip);
		write_char(':'); itoa_short(state.server_port); write_char('\n');
		state.enabled = 1;
	}
	else {
		print_string_newline_no_syslog("Syslog is already running");
	}
}

void syslog_stop(void) __banked
{
	state.enabled = 0;
	if (state.syslog_conn != 0) {
		uip_udp_remove(state.syslog_conn);
		state.syslog_conn = 0;
		print_string_newline_no_syslog("Stopped syslog");
	} else {
		print_string_newline_no_syslog("Syslog is not running");
	}
}

void syslog_callback(uint16_t lport) __banked
{
	uint16_t syslog_hdr;
	if (!state.syslog_conn || lport != state.syslog_conn->lport)
		return;

	if ((state.readptr != state.writeptr) && state.line_available)
	{
		__xdata int16_t log_size = state.writeptr - state.readptr;
		if (log_size < 0)
			log_size += LOGBUF_SIZE;
		
		// Skipping linefeeds at the start of the log line
		__xdata uint16_t log_start = state.readptr;
		while (log_size > 0 && logbuf[log_start] == '\n') {
			log_start = (log_start + 1) & (LOGBUF_SIZE - 1);
			log_size--;
		}

		// Skipping linefeeds and whitespaces at the end of the log line
		__xdata uint16_t log_end = state.writeptr;
		while ( (log_size > 0) && 
				((logbuf[(log_end-1) & (LOGBUF_SIZE - 1)] == '\n') ||
				 (logbuf[(log_end-1) & (LOGBUF_SIZE - 1)] == ' ')))
		{
			log_end = (log_end - 1) & (LOGBUF_SIZE - 1);
			log_size--;
		}

		if (log_size == 0) {
			state.readptr = state.writeptr;
			state.line_available = 0;
			return;
		}

		memcpyc(SYSLOG_P, "<14>", 4); // Syslog priority prefix

		/* RFC 3164 puts a hostname between the priority and the text, and
		 * we were leaving that slot empty. A receiver still has to fill
		 * the field, so it takes the first word of the message instead:
		 * every line arrives attributed to "STP:" or "REGGET:" or
		 * whatever the log happens to start with, and the sender cannot
		 * be selected on at all. Send our own name and the field means
		 * something. Skipped when the name is empty, so we never emit a
		 * lone separator. */
		syslog_hdr = strlen_x(hostname);
		if (syslog_hdr) {
			memcpy(SYSLOG_P + 4, hostname, syslog_hdr);
			SYSLOG_P[4 + syslog_hdr] = ' ';
			syslog_hdr += 5;
		} else {
			syslog_hdr = 4;
		}

		if (log_end < log_start) {
			memcpy(SYSLOG_P + syslog_hdr, logbuf + log_start, LOGBUF_SIZE - log_start);
			memcpy(SYSLOG_P + syslog_hdr + LOGBUF_SIZE - log_start, logbuf, log_end);
		} else {
			 memcpy(SYSLOG_P + syslog_hdr, logbuf + log_start, log_end - log_start);
		}

		uip_udp_send(log_size + syslog_hdr);
		state.readptr = state.writeptr;
		state.line_available = 0;
	}
}

/* Scratch for syslog_flush()/sf_arp_resolved() - module scope, not
 * function-local: this file is not built --stack-auto (see snmp.c's
 * comment on the same subject), so a plain local is overlaid into
 * internal RAM, which this build has little spare of. */
static __xdata struct uip_udp_conn * __xdata sf_conn;
static __xdata uint8_t sf_wait;
static __xdata uint16_t sf_target[2];
static __xdata uint8_t sf_j;
static __code const uint16_t sf_broadcast_ip[2] = {0xffff, 0xffff};

/* Is dest already resolved in the ARP cache (or the default gateway,
 * if dest is off-subnet - same target uip_arp_out() would resolve to)?
 * Duplicates that decision read-only, rather than calling into
 * uip_arp.c, because uip_arp.c is BANK1 - already at its code-space
 * limit (see the .map report) - while this file (BANK2) still has
 * room. */
static uint8_t sf_arp_resolved(__xdata uip_ipaddr_t *dest)
{
	if (uip_ipaddr_cmpc(*dest, sf_broadcast_ip))
		return 1;

	if (!uip_ipaddr_maskcmp(*dest, uip_hostaddr, uip_netmask))
		uip_ipaddr_copy(sf_target, uip_draddr);
	else
		uip_ipaddr_copy(sf_target, *dest);

	for (sf_j = 0; sf_j < UIP_ARPTAB_SIZE; sf_j++) {
		if (uip_ipaddr_cmpx(sf_target, arp_table[sf_j].ipaddr))
			return 1;
	}
	return 0;
}

/* Mirrors uip.c's own (private) BUF macro - #define BUF ((__xdata
 * struct uip_tcpip_hdr *)&uip_buf[UIP_LLH_LEN]) - using only public
 * declarations (struct uip_tcpip_hdr is in uip.h), so sf_trigger_arp()
 * below can address the IP header's destipaddr field without needing
 * anything from uip_arp.c - see sf_arp_resolved()'s comment on why
 * that file is off limits for new code. */
#define SF_IPBUF ((__xdata struct uip_tcpip_hdr *)&uip_buf[UIP_LLH_LEN])

/* Actively triggers ARP resolution for dest by emitting a request.
 * Deliberately does not touch logbuf or uip_udp_conn: unlike calling
 * uip_arp_out() on an already-pending real send (which would
 * substitute the request for whatever packet syslog_callback() just
 * built - see its own doc comment, and there would be nothing left to
 * retry from), this builds its own throwaway probe packet first, so
 * syslog_flush() below can check resolution *before* ever attempting
 * the real send - see its comment for why that matters. */
static void sf_trigger_arp(__xdata uip_ipaddr_t *dest)
{
	uip_ipaddr_copy(SF_IPBUF->destipaddr, *dest);
	uip_arp_out();
	if (uip_len > 0)
		tcpip_output();
}

/* Forces an out-of-band drain of the syslog ring buffer and sends it
 * right away, instead of waiting for the next main-loop pass (via
 * handle_tx()'s periodic UDP walk, which normally calls
 * syslog_callback() above once per loop) to notice it. Needed before
 * reset_chip(): that call never returns, so a message queued right
 * before a reboot would otherwise sit in logbuf unsent forever - see
 * the reboot log calls in cmd_parser.c/httpd.c/rtlplayground.c. A
 * no-op when syslog is not running or nothing is queued.
 *
 * Also copes with a cold ARP cache, which would otherwise silently
 * lose exactly the message this function exists to protect:
 * uip_arp_out() drops whatever packet is pending in favour of an ARP
 * request on a cache miss (see its own doc comment), and
 * syslog_callback() has *already* marked the buffered data as sent by
 * the time that happens (it advances readptr right after building the
 * packet - uip_udp_send() only prepares it, the actual
 * resolve-and-transmit is the caller's job, below). Normally that is
 * invisible: syslog_callback() runs on every main-loop pass, so a
 * dropped first attempt just means the next pass's packet succeeds
 * instead. This function runs exactly once, so it resolves first (if
 * needed - sf_trigger_arp() above, which never touches the real
 * message) and waits briefly for the reply, *then* makes a single
 * send attempt - never a retry-after-send: an earlier version of this
 * function detected a cold cache only after sending and re-queued the
 * same data to try again, which could race a syslog_callback() call
 * triggered independently (e.g. by handle_rx() in the wait loop,
 * processing an unrelated packet that happens to match this
 * connection) into sending the same message twice. */
void syslog_flush(void) __banked
{
	/* syslog_conn's declared type (a generic pointer, matching what
	 * uip_udp_new() returns in syslog_start()) is a different pointer
	 * representation than uip_udp_conn's (__xdata struct uip_udp_conn
	 * * __xdata) - SDCC rejects the implicit conversion, so cast once
	 * here and reuse sf_conn below instead of repeating it. */
	sf_conn = (__xdata struct uip_udp_conn * __xdata)state.syslog_conn;

	if (!sf_conn)
		return;
	if (state.readptr == state.writeptr && !state.line_available)
		return;

	if (!sf_arp_resolved(&sf_conn->ripaddr)) {
		sf_trigger_arp(&sf_conn->ripaddr);
		/* ~20 ticks: long enough for a LAN round trip, short enough
		 * not to stall a reboot noticeably if the server (or the
		 * gateway, for an off-subnet server) is unreachable. */
		for (sf_wait = 0; sf_wait < 20 &&
		     !sf_arp_resolved(&sf_conn->ripaddr); sf_wait++) {
			delay(1);
			handle_rx();
		}
	}

	uip_udp_conn = sf_conn;
	uip_process(UIP_UDP_TIMER);
	if (uip_len > 0) {
		uip_arp_out();
		tcpip_output();
	}
}
