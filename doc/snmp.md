# SNMP

This firmware ships a small read-only SNMPv1 / SNMPv2c agent on
UDP port 161. Its purpose is to expose the state that already lives
on the switch (system identity, uptime, per-port link state, per-port
counters, the L2/MAC address table, configured VLANs, LLDP TX status)
to any off-the-shelf
monitoring tool - Grafana with `snmp_exporter`, LibreNMS, Zabbix, PRTG,
`net-snmp` from the shell, etc. There is no support for SNMPv3, no
support for `SetRequest`, and no traps.

## Enabling the agent

The agent is compiled in but disabled by default. From the serial
console:

```
snmp on
```

To make the change persistent, add the same line to the running
configuration (via the web UI's *System* page or by editing
`config.txt` before flashing).

Configuration commands:

| command | effect |
|---------|--------|
| `snmp on` | start the agent |
| `snmp off` | stop the agent |
| `snmp community <string>` | change the read community (default `public`) |
| `snmp contact <string>` | set `sysContact.0` (default empty) |
| `snmp location <string>` | set `sysLocation.0` (default empty) |
| `snmp` (no argument) | print current status |

`sysName.0` is served from the switch's `hostname` variable and
therefore follows the `hostname` command.

## Testing from the LAN

```
snmpwalk -v2c -c public 192.168.10.247 system
snmpwalk -v2c -c public 192.168.10.247 ifTable
snmpwalk -v2c -c public 192.168.10.247 dot1dTpFdbTable
snmpwalk -v2c -c public 192.168.10.247 dot1qVlanStaticTable
```

Or, to browse everything the agent serves under mib-2:

```
snmpwalk -v2c -c public 192.168.10.247 .1.3.6.1.2.1
```

LLDP-MIB lives outside mib-2 (see below), so it needs its own walk:

```
snmpwalk -v2c -c public 192.168.10.247 .1.0.8802.1.1.2.1
```

## Served MIB

### `system` group (`.1.3.6.1.2.1.1`)

| OID | value | source |
|-----|-------|--------|
| `sysDescr.0` | `RTLPlayground <ver> on <machine>` | build info |
| `sysObjectID.0` | `.1.3.6.1.3.99.99.1` (unregistered) | fixed |
| `sysUpTime.0` | TimeTicks since boot | `ticks / 2` |
| `sysContact.0` | `snmp contact` value | config |
| `sysName.0` | `hostname` | config |
| `sysLocation.0` | `snmp location` value | config |
| `sysServices.0` | `3` (physical + datalink) | fixed |

### `interfaces` group (`.1.3.6.1.2.1.2`)

`ifIndex` runs from 1 up to the number of ports on the device (as
reported by `ifNumber.0`). Physical port labels are mapped to
`ifIndex` in the same order the CLI's `stat` command lists them.

Served ifTable columns:

| column | OID suffix | type | value |
|--------|------------|------|-------|
| `ifIndex` | `.1.1.<n>` | INTEGER | `n` |
| `ifDescr` | `.1.2.<n>` | OCTET STRING | `port <label>` |
| `ifType` | `.1.3.<n>` | INTEGER | `6` (ethernetCsmacd) |
| `ifMtu` | `.1.4.<n>` | INTEGER | `1500` |
| `ifSpeed` | `.1.5.<n>` | Gauge32 | link speed in bits/s (capped at 2^32-1 for 5 G / 10 G links) |
| `ifPhysAddress` | `.1.6.<n>` | OCTET STRING | CPU MAC address |
| `ifAdminStatus` | `.1.7.<n>` | INTEGER | always `1` (up) |
| `ifOperStatus` | `.1.8.<n>` | INTEGER | `1` (up) if link is up, `2` (down) otherwise |
| `ifInOctets` | `.1.10.<n>` | Counter32 | RX packet count (byte counters are not exposed by the ASIC) |
| `ifInUcastPkts` | `.1.11.<n>` | Counter32 | RX packet count |
| `ifInErrors` | `.1.14.<n>` | Counter32 | error packet count |
| `ifOutOctets` | `.1.16.<n>` | Counter32 | TX packet count (byte counters are not exposed by the ASIC) |
| `ifOutUcastPkts` | `.1.17.<n>` | Counter32 | TX packet count |
| `ifOutErrors` | `.1.20.<n>` | Counter32 | error packet count |

### `ipNetToMediaTable` (`.1.3.6.1.2.1.4.22`) - the ARP cache

The switch's own ARP cache (up to 8 entries, uIP's `UIP_ARPTAB_SIZE`),
i.e. the IP-to-MAC mappings the switch itself has learned for its
management IP stack. This is not per-port data - it has nothing to do
with the L2 MAC address table (`/l2.json` / the CLI's L2 table), which
tracks what the switch has learned on the wire.

Served ipNetToMediaTable columns:

| column | OID suffix | type | value |
|--------|------------|------|-------|
| `ipNetToMediaIfIndex` | `.1.1.<n>` | INTEGER | always `1` (see limitation below) |
| `ipNetToMediaPhysAddress` | `.1.2.<n>` | OCTET STRING | MAC address |
| `ipNetToMediaNetAddress` | `.1.3.<n>` | IpAddress | IP address |
| `ipNetToMediaType` | `.1.4.<n>` | INTEGER | always `3` (dynamic) |

`<n>` is the 1-based ARP cache slot number (1-8), not a real index
value - see Limitations below.

### `ifXTable` (`.1.3.6.1.2.1.31.1.1.1`)

Just the two columns worth the extra code size:

| column | OID suffix | type | value |
|--------|------------|------|-------|
| `ifName` | `.1.<n>` | OCTET STRING | the port's configured name (`port <n> name ...`) |
| `ifHighSpeed` | `.15.<n>` | Gauge32 | link speed in Mbit/s, uncapped (use this instead of `ifSpeed` for 2.5 G/5 G/10 G links, which saturate `ifSpeed`'s 32-bit bits/s range) |

No `ifHCInOctets`/`ifHCInUcastPkts`/etc. (64-bit counters): the ASIC
does not give the CPU real 64-bit byte counters any more than it does
for the 32-bit `ifInOctets`/`ifOutOctets` above, so a Counter64 column
here would just re-encode the same packet count in a wider format for
no benefit.

### `dot1dTpFdbTable` (`.1.3.6.1.2.1.17.4.3.1`) - the L2/MAC address table

The switch's forwarding database - what MAC addresses it has learned
on which port, the same data as `/l2.json` / the CLI's L2 table. This
is the most commonly polled table on a managed switch (asset tracking,
NAC, topology tools).

| column | OID suffix | type | value |
|--------|------------|------|-------|
| `dot1dTpFdbAddress` | `.1.<n>` | OCTET STRING | MAC address |
| `dot1dTpFdbPort` | `.2.<n>` | INTEGER | `ifIndex` of the port the entry was learned on |
| `dot1dTpFdbStatus` | `.3.<n>` | INTEGER | `learned(3)` for dynamic entries, `mgmt(5)` for statically configured ones |

`<n>` is the raw ASIC L2 hash-table slot (0-4095) plus one, not the
MAC address - see Limitations below. `GetNext` walks the table using
the ASIC's own "next occupied slot" hardware primitive rather than
probing all 4096 slots per step, so a full `snmpwalk` stays fast even
though the index space is large and sparse.

### `dot1qVlanStaticTable` (`.1.3.6.1.2.1.17.7.1.4.3.1`, Q-BRIDGE-MIB) - configured VLANs

The switch's configured VLANs, the same data as the web UI's VLAN page
/ the CLI's `vlan show`. Unlike `dot1dTpFdbTable` and
`ipNetToMediaTable` above, the index here is exactly what RFC 2674
specifies - `dot1qVlanIndex` is the VLAN ID itself (1-4094), no
fake-index caveat needed.

| column | OID suffix | type | value |
|--------|------------|------|-------|
| `dot1qVlanStaticName` | `.1.<vlan>` | OCTET STRING | the name set via `vlan <id> <name> ...`, empty if unnamed |
| `dot1qVlanStaticEgressPorts` | `.2.<vlan>` | OCTET STRING | member ports (see below) |
| `dot1qVlanStaticUntaggedPorts` | `.4.<vlan>` | OCTET STRING | untagged member ports (see below) |
| `dot1qVlanStaticRowStatus` | `.5.<vlan>` | INTEGER | always `active(1)` - only existing VLANs are served |

**Not a standard `PortList`**: RFC 2674 specifies a bit-per-port
octet string with the MSB of the first octet as port 1. This agent
instead reports a plain 16-bit bitmask, high byte first, with bit *N*
set for physical port *N* - the same numbering `vlan_settings.members`
and the `vlan <id> <port>...` CLI command use, not `ifIndex`. Tools
that decode `PortList` per the RFC will show the wrong ports; reading
the two octets as a raw bitmask gives the right membership.

There is no ASIC "next configured VLAN" primitive (unlike
`dot1dTpFdbTable`'s hash table), so `GetNext` scans forward one VLAN
ID at a time until it finds one that exists - the same approach the
web UI's VLAN list already uses (`send_vlanlist()` in
`httpd/page_impl.c`). This is fine in practice (VLANs are normally few
and low-numbered) but a walk could be slow if very high VLAN IDs are
used with large gaps between them.

### LLDP-MIB (`.1.0.8802.1.1.2.1`, IEEE 802.1AB)

**TX-only**: this firmware does not process received LLDP frames, so
there is no `lldpRemTable` (neighbor/topology data) - only what this
switch itself advertises. Lives outside mib-2 under IEEE's own arc, so
it will not appear in a plain `snmpwalk` of `.1.3.6.1.2.1`.

`lldpLocalSystemData` (`.3`, scalars):

| OID | OID suffix | type | value |
|-----|------------|------|-------|
| `lldpLocChassisIdSubtype.0` | `.3.1.0` | INTEGER | always `4` (macAddress) |
| `lldpLocChassisId.0` | `.3.2.0` | OCTET STRING | CPU MAC address |
| `lldpLocSysName.0` | `.3.3.0` | OCTET STRING | `hostname` |
| `lldpLocSysDesc.0` | `.3.4.0` | OCTET STRING | machine model string |

`lldpPortConfigTable` (`.1.6.1`, one column):

| column | OID suffix | type | value |
|--------|------------|------|-------|
| `lldpPortConfigAdminStatus` | `.1.6.1.2.<n>` | INTEGER | `txOnly(3)` if LLDP and this port's send bit are both enabled, `disabled(4)` otherwise |

### Limitations

* Only `GetRequest`, `GetNextRequest` and `GetBulkRequest` are
  accepted. `GetBulk` is answered with one variable-binding per
  request-varbind - non-repeaters and max-repetitions are ignored.
  Tools such as `snmpbulkwalk` still work but do more round trips
  than they would against a full-featured agent.
* Received packets are matched against a single, static community
  string; anyone with the community can walk the MIB. Do not enable
  the agent on interfaces where this is not acceptable.
* No IPv6, no SNMPv3. Only the columns documented above - no ifXTable
  64-bit counters, no `dot1dBase`/`dot1dStp` groups, no LLDP
  `lldpRemTable` (see the LLDP-MIB section above).
* Byte counters are not exposed by the ASIC to the CPU port
  directly; `ifInOctets` / `ifOutOctets` report the RX / TX packet
  count so that graphs still show growth over time.
* `ipNetToMediaTable`'s real INDEX is `{ ifIndex, ipNetToMediaNetAddress }`
  (RFC 1213); this agent indexes by ARP slot number instead, and
  `ipNetToMediaIfIndex` is a fixed `1` rather than the interface the
  entry was actually learned on (which uIP's ARP cache does not
  record). `snmpwalk`/`snmpget` still return correct IP/MAC values -
  only tooling that parses the index itself to recover the IP address,
  instead of reading `ipNetToMediaNetAddress`, is affected.
* `dot1dTpFdbTable`'s real INDEX is `dot1dTpFdbAddress` (the MAC
  itself); this agent indexes by raw ASIC hash-table slot instead
  and reports the MAC as an ordinary value column. Same caveat as
  above: `snmpwalk`/`snmpget` return correct values, but tooling that
  parses the OID index to recover the MAC (instead of reading
  `dot1dTpFdbAddress`) will not work against this agent.
* `dot1dTpFdbPort` does not resolve LAG membership: a port that is a
  LAG member is reported as its own `ifIndex`, matching `/l2.json`'s
  `port` field, not the LAG's.
* LLDP-MIB's `lldpPortConfigAdminStatus` only ever reports `txOnly`
  or `disabled` - `rxOnly` and `txAndRx` never apply, since this
  agent never processes received LLDP frames (see above).
