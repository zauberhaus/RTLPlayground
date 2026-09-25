#ifndef __PAGE_IMPL_H__
#define __PAGE_IMPL_H__

#include <stdbool.h>

extern __code const uint8_t * __code const HTTP_RESPONCE_TXT;

bool send_counters(uint8_t phys_port);
void send_status(void);
void send_vlan(uint16_t vlan);
void send_basic_info(void);
void send_bandwidth(void);
void send_eee(void);
void send_l2(uint16_t idx);
void l2_delete(uint16_t idx);
void send_mirror(void);
void send_mtu(void);
void send_config(void);
void send_cmd_log(void);
void send_lag(void);
void send_stp(void);
/* Lives in page_impl_lldp.c, banked into BANK3 - see send_snmp()'s
 * comment below for why __banked is required here. */
void send_lldp(void) __banked;
/* Lives in page_impl_snmp.c, banked into BANK3 (unlike the other
 * send_*() functions here, which share page_impl.c's BANK1 with their
 * caller in httpd.c) - __banked is required so the call crosses banks
 * correctly instead of silently jumping into whatever is mapped at
 * that address in the caller's own bank. */
void send_snmp(void) __banked;
void send_vlanlist(void);

/*  Convert only the lower nibble to ascii HEX char.
    For convenience the upper nibble is masked out.
*/
inline char itohex(uint8_t val) {
	// Ignore upper nibble for convenience.
	val &= 0x0f;
	val -= 10;

	// 10 or above
	if ((int8_t)val >= 0)
		val += ('a' - '0' - 10);

	return val + ('0' + 10);
}

#endif
