import asyncio
from hsoc.ingest.syslog_server import process_raw_syslog_line

async def main():
    raw = '<13>Oct 26 22:15:00 auth-srv-02 sshd[9998]: @#$%^&* INVALID CORRUPTED STREAM'
    res = await process_raw_syslog_line(raw)
    print("Result:", res)

asyncio.run(main())
