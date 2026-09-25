/*
 * The SNMP status page lives in its own translation unit, banked into
 * BANK3 like the snmp module itself: BANK1 (where the other send_*()
 * page renderers live, see page_impl.c) has no headroom left for it.
 */
#pragma codeseg BANK3
#pragma constseg BANK3

#include <stdint.h>
#include "rtl837x_common.h"
#include "snmp.h"
#include "page_impl.h"

extern __xdata uint8_t outbuf[TCP_OUTBUF_SIZE];
extern __xdata uint16_t slen;
extern __xdata struct snmp_state snmp_state;

static void bool_char(char c)
{
	outbuf[slen++] = c ? '1' : '0';
}

/* Mirrors json_char_to_html() in page_impl.c; duplicated locally so this
 * translation unit needs no cross-bank call into BANK1. */
static void json_char(uint8_t c)
{
	if (c < 0x20 || c > 0x7e || c == '"' || c == '\\')
		c = '.';
	outbuf[slen++] = c;
}

void send_snmp(void)
{
	slen = strtox(outbuf, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n");

	slen += strtox(outbuf + slen, "{\"on\":");
	bool_char(snmp_state.enabled);
	slen += strtox(outbuf + slen, ",\"community\":\"");
	for (uint8_t i = 0; snmp_state.community[i]; i++)
		json_char(snmp_state.community[i]);
	slen += strtox(outbuf + slen, "\",\"contact\":\"");
	for (uint8_t i = 0; snmp_state.contact[i]; i++)
		json_char(snmp_state.contact[i]);
	slen += strtox(outbuf + slen, "\",\"location\":\"");
	for (uint8_t i = 0; snmp_state.location[i]; i++)
		json_char(snmp_state.location[i]);
	slen += strtox(outbuf + slen, "\"}");
}
