#!/usr/bin/env python3
"""
printer_idle_guard.py -- keep a Brother ink tank printer's COLOUR nozzles wet.

What clogs is whichever nozzle sits unused. Printing black all week does
nothing for cyan/magenta/yellow, so this tracks colour specifically.

Runs once a week, preferring Monday night. Meant to be invoked from a DAILY
cron job -- it tracks which ISO week it last handled, so if Monday's cron
fires while the machine is asleep/off/away, the next day it runs catches up
instead, then it holds off again until the following Monday's week begins.

Two modes:

  Default (no config needed) -- guarantees a four-ink page once a week
  regardless of what else you print. Correct, dumb, ~52 pages a year.

  Counter-aware (set COLOUR_COUNTER_ID) -- reads Brother's proprietary
  per-colour page counter and skips our page if you already printed in
  colour this week. Needs a one-time discovery step; see --dump.

Usage:
    python printer_idle_guard.py            # normal daily cron run
    python printer_idle_guard.py --now      # force a print (test), bypassing the weekly gate
    python printer_idle_guard.py --dump     # show raw counters, for discovery

No third-party packages required.
"""

import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------- settings --

# No fixed IP -- discovered fresh via Bonjour/mDNS on every run, since a
# laptop moves between networks and DHCP leases change. See discover_ip().
PRINTER_MDNS_NAME = "Brother DCP-T535DW"          # Bonjour service instance name
PRINTER_SERVICE_TYPES = ["_ipps._tcp", "_ipp._tcp"]  # tried in order
DISCOVER_TIMEOUT = 3.0                            # seconds to wait for mDNS replies

PRINTER_NAME = "Brother_DCP_T535DW"  # OS print queue name; "" = system default

# Leave as None until you've run --dump and identified your colour counter.
# Discovery instructions are at the bottom of this file.
COLOUR_COUNTER_ID = None             # e.g. 0x02

# -----------------------------------------------------------------------------

STATE = Path(__file__).with_name("printer_idle_guard.state.json")
PAGE = Path(__file__).with_name("nozzle_page.pdf")

COMMUNITY = "public"
OID_TOTAL_PAGES = (1, 3, 6, 1, 2, 1, 43, 10, 2, 1, 4, 1, 1)          # standard MIB
OID_BR_COUNTER = (1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 4, 2, 1, 5, 5, 10, 0)


# --------------------------------------------------------------- BER / SNMP --

def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, payload):
    return bytes([tag]) + _len(len(payload)) + payload


def _int(v):
    body = b"\x00" if v == 0 else v.to_bytes((v.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(0x02, body)


def _oid(arcs):
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        if arc < 0x80:
            body += bytes([arc])
        else:
            chunk = bytearray([arc & 0x7F])
            arc >>= 7
            while arc:
                chunk.insert(0, (arc & 0x7F) | 0x80)
                arc >>= 7
            body += bytes(chunk)
    return _tlv(0x06, body)


def _read_tlv(buf, i):
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n


def snmp_get(ip, oid, timeout=4.0):
    """Return (tag, value_bytes) of the varbind value."""
    varbind = _tlv(0x30, _oid(oid) + _tlv(0x05, b""))
    pdu = _tlv(0xA0, _int(int(time.time()) & 0x7FFFFFFF) + _int(0) + _int(0)
               + _tlv(0x30, varbind))
    packet = _tlv(0x30, _int(0) + _tlv(0x04, COMMUNITY.encode()) + pdu)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (ip, 161))
        data, _ = s.recvfrom(4096)

    _, body, _ = _read_tlv(data, 0)          # outer SEQUENCE
    i = 0
    _, _, i = _read_tlv(body, i)             # version
    _, _, i = _read_tlv(body, i)             # community
    _, pdu_body, _ = _read_tlv(body, i)      # GetResponse

    j = 0
    _, _, j = _read_tlv(pdu_body, j)         # request-id
    _, err, j = _read_tlv(pdu_body, j)       # error-status
    _, _, j = _read_tlv(pdu_body, j)         # error-index
    if int.from_bytes(err, "big"):
        raise RuntimeError(f"SNMP error-status {int.from_bytes(err, 'big')}")

    _, vblist, _ = _read_tlv(pdu_body, j)    # varbind list
    _, vb, _ = _read_tlv(vblist, 0)          # varbind
    _, _, k = _read_tlv(vb, 0)               # name (OID)
    tag, value, _ = _read_tlv(vb, k)
    return tag, value


def get_int(ip, oid):
    _, v = snmp_get(ip, oid)
    return int.from_bytes(v, "big")


# ------------------------------------------------------------- discovery ----

def _dns_sd(args, duration):
    """Run `dns-sd` (mDNS/Bonjour, macOS-only) for `duration` seconds and
    return whatever it printed. dns-sd streams updates forever, so there's
    no built-in one-shot query -- we just sample it briefly and kill it."""
    try:
        proc = subprocess.Popen(["dns-sd"] + args, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True)
    except FileNotFoundError:
        return ""
    time.sleep(duration)
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return out


def discover_ip(name=PRINTER_MDNS_NAME, timeout=DISCOVER_TIMEOUT):
    """Resolve the printer's current IPv4 via Bonjour. Returns None if it
    isn't present on whatever network we're on right now."""
    for service in PRINTER_SERVICE_TYPES:
        lookup = _dns_sd(["-L", name, service, "local"], timeout)
        m = re.search(r"can be reached at (\S+):(\d+)", lookup)
        if not m:
            continue
        host = m.group(1).rstrip(".")
        resolved = _dns_sd(["-G", "v4", host], timeout)
        for line in resolved.splitlines():
            if re.match(r"\S+\s+Add\s", line):
                ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                if ip:
                    return ip.group(1)
    return None


def parse_br_counters(blob):
    """Brother packs counters as [id][01][len][big-endian value]... 0xFF."""
    out, i = {}, 0
    while i + 2 < len(blob) and blob[i] != 0xFF:
        cid = blob[i]
        length = blob[i + 2]
        out[cid] = int.from_bytes(blob[i + 3:i + 3 + length], "big")
        i += 3 + length
    return out


# ------------------------------------------------------------- test page ----

def write_page():
    stamp = datetime.now().strftime("%Y-%m-%d")
    ops = [
        "0 0 0 rg 60 700 110 55 re f",        # K
        "0 1 1 rg 185 700 110 55 re f",       # C
        "1 0 1 rg 310 700 110 55 re f",       # M
        "1 1 0 rg 435 700 110 55 re f",       # Y
        "0 0.5 1 rg 60 630 155 55 re f",      # mixed, exercises C+M
        "1 0.5 0 rg 235 630 155 55 re f",     # mixed, exercises M+Y
        "0.6 0.6 0.6 rg 410 630 135 55 re f", # composite grey
        f"BT /F1 10 Tf 60 595 Td 0 0 0 rg (Nozzle exercise - K C M Y - {stamp}) Tj ET",
    ]
    stream = "\n".join(ops).encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for n, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs)+1}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()
    PAGE.write_bytes(bytes(out))
    return PAGE


def send_to_printer(path):
    if sys.platform == "win32":
        os.startfile(str(path), "print")
    else:
        cmd = ["lp"] + (["-d", PRINTER_NAME] if PRINTER_NAME else []) + [str(path)]
        subprocess.run(cmd, check=True)


# ------------------------------------------------------------------- main ----

def dump():
    """Discovery helper: show every counter Brother exposes."""
    print("Looking for the printer on this network...")
    ip = discover_ip()
    if ip is None:
        print(f"'{PRINTER_MDNS_NAME}' not found via Bonjour on this network. Nothing to dump.")
        return 1
    print(f"Found at {ip}")
    try:
        print(f"Total pages (standard MIB): {get_int(ip, OID_TOTAL_PAGES)}")
    except Exception as exc:
        print(f"Standard page count unavailable: {exc}")
    try:
        _, blob = snmp_get(ip, OID_BR_COUNTER)
    except Exception as exc:
        print(f"brInfoCounter unavailable: {exc}")
        return 1
    print(f"\nbrInfoCounter raw: {blob.hex(' ')}\n")
    print("  ID    value")
    for cid, val in sorted(parse_br_counters(blob).items()):
        print(f"  0x{cid:02X}  {val}")
    print("\nRun --dump, print ONE colour page by hand, run --dump again.")
    print("Whichever ID went up by 1 is your COLOUR_COUNTER_ID.")
    return 0


def week_id(dt):
    """ISO (year, week) as a string. ISO weeks run Monday-Sunday, which is
    exactly the catch-up window we want: whichever day this week we first
    manage to run becomes 'this week's run', and it won't fire again until
    the week rolls over next Monday."""
    y, w, _ = dt.isocalendar()
    return f"{y}-W{w:02d}"


def main():
    if "--dump" in sys.argv:
        return dump()

    force = "--now" in sys.argv
    now = datetime.now()  # local time -- cron's schedule and "Monday night" are both local-clock concepts
    this_week = week_id(now)
    try:
        state = json.loads(STATE.read_text())
    except Exception:
        state = {}

    if not force and state.get("last_week_done") == this_week:
        print(f"Already handled week {this_week}.")
        return 0

    ip = discover_ip()
    if ip is None:
        print(f"'{PRINTER_MDNS_NAME}' not found via Bonjour on this network. Exiting.")
        return 0

    if now.weekday() == 0:
        print(f"Monday run ({this_week}).")
    else:
        print(f"Catch-up run for {this_week} ({now.strftime('%A')} -- missed Monday).")

    colour_count = None
    if COLOUR_COUNTER_ID is not None:
        try:
            _, blob = snmp_get(ip, OID_BR_COUNTER)
            colour_count = parse_br_counters(blob).get(COLOUR_COUNTER_ID)
            print(f"Colour page counter: {colour_count}")
        except Exception as exc:
            print(f"Counter read failed ({exc}); printing the guard page regardless.")

    if not force and colour_count is not None and colour_count != state.get("colour_count"):
        print("Colour activity already detected this week; skipping guard page.")
        state["colour_count"] = colour_count
        state["last_week_done"] = this_week
        STATE.write_text(json.dumps(state))
        return 0

    print("Printing four-ink exercise page...")
    send_to_printer(write_page())
    state["last_week_done"] = this_week
    if colour_count is not None:
        state["colour_count"] = colour_count + 1

    STATE.write_text(json.dumps(state))
    return 0


if __name__ == "__main__":
    sys.exit(main())

# ---------------------------------------------------------------------------
# DISCOVERING YOUR COLOUR COUNTER
#
#   1. python printer_idle_guard.py --dump      -> note the ID/value table
#   2. Print one page containing colour, by hand
#   3. python printer_idle_guard.py --dump      -> compare
#
# The ID that increased by exactly 1 is your colour page counter. Put it in
# COLOUR_COUNTER_ID above. An ID that ALSO moves when you print black-only is
# the total counter, not the colour one -- test that case before deciding.
#
# If nothing on your model distinguishes colour from mono, leave it as None.
# The default still guarantees the nozzles fire once a week regardless.
# ---------------------------------------------------------------------------
