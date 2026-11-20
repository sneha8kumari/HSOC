import sys
import asyncio

print("1. Importing modules...", flush=True)
from hsoc.ingest.syslog_server import process_raw_syslog_line
from hsoc.streaming.bus import reset_event_bus
from hsoc.db import init_db

print("2. Initializing db...", flush=True)
init_db()
print("3. Resetting event bus...", flush=True)
reset_event_bus()

async def test():
    raw = '<13>Oct 26 22:15:00 auth-srv-02 sshd[9999]: Failed password for root from 198.51.100.99 port 54321 ssh2'
    print("4. Before process_raw_syslog_line...", flush=True)
    res = await process_raw_syslog_line(raw)
    print("5. After process_raw_syslog_line:", res, flush=True)

print("6. Calling asyncio.run...", flush=True)
asyncio.run(test())
print("7. Test finished successfully!", flush=True)
