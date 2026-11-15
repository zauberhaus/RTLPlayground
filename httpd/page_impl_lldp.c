/*
 * The LLDP status page lives in its own translation unit, banked into
 * BANK3 (like the lldp module itself, rtl837x_lldp.c): BANK1 (where
 * the other send_*() page renderers live, see page_impl.c) has no
 * headroom left for it. send_snmp() in page_impl_snmp.c follows the
 * same pattern for the same reason.
 */
#pragma codeseg BANK3
#pragma constseg BANK3

#include <stdint.h>
#include "rtl837x_common.h"
#include "machine.h"
#include "page_impl.h"

extern __xdata uint8_t outbuf[TCP_OUTBUF_SIZE];
extern __xdata uint16_t slen;
extern __xdata uint16_t lldp_physical_port_status;
extern __xdata bool lldp_enabled;
extern __code const struct machine machine;

static void bool_char(char c)
{
	outbuf[slen++] = c ? '1' : '0';
}

/* Mirrors itoa_html() in page_impl.c; duplicated locally so this
 * translation unit needs no cross-bank call into BANK1. */
static void itoa_char(uint8_t v)
{
	uint8_t t = v / 100;
	uint8_t print_zeros = t;
	if (print_zeros)
		outbuf[slen++] = '0' + t;
	t = (v / 10) % 10;
	print_zeros |= t;
	if (print_zeros)
		outbuf[slen++] = '0' + t;
	outbuf[slen++] = '0' + (v % 10);
}

void send_lldp(void) __banked
{
	slen = strtox(outbuf, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n");

	slen += strtox(outbuf + slen, "{\"on\":");
	bool_char(lldp_enabled);
	slen += strtox(outbuf + slen, ",\"port_status\": [");

	/* Tagged by portNum rather than array position: the client's own
	 * port list is sorted by physical port number, which does not
	 * generally match this loop's logical-port iteration order. */
	for (uint8_t port = machine.min_port; port <= machine.max_port; port++) {
		slen += strtox(outbuf + slen, "{\"portNum\":");
		itoa_char(machine.log_to_phys_port[port]);
		slen += strtox(outbuf + slen, ",\"on\":");
		/* bool_char() takes a single-byte char: computing the shift+AND
		 * directly as its argument lets SDCC narrow the whole
		 * expression to 8 bits (since that is all the destination
		 * needs), silently losing ports >= 8 whose bit lives in the
		 * high byte. Reducing to a proper 0/1 first (?: has no
		 * narrower destination to optimize into, unlike a bare
		 * function argument) avoids that. */
		bool_char((((uint16_t)1 << machine.log_to_phys_port[port]) & lldp_physical_port_status) ? 1 : 0);
		slen += strtox(outbuf + slen, "},");
	}
	slen -= 1; // remove comma

	slen += strtox(outbuf + slen, "]}");
}
