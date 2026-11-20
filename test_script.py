import asyncio
import re
from hsoc.db import init_db, SessionLocal, EventORM
from hsoc.ingest.parsers import PARSER_REGISTRY
from hsoc.ingest.mapper import map_to_event
from hsoc.ingest.enrich import enrich
from hsoc.streaming.bus import get_event_bus, StreamMessage, reset_event_bus

init_db()
reset_event_bus()

async def test():
    raw = '<13>Oct 26 22:15:00 auth-srv-02 sshd[9999]: Failed password for root from 198.51.100.99 port 54321 ssh2'
    clean = re.sub(r'^<\d{1,3}>', '', raw).strip()
    p_fn = PARSER_REGISTRY['linux_auth']
    p_dict = p_fn(clean)
    mapped = map_to_event(p_dict, 'linux_auth')
    enriched = enrich(mapped)

    print('Writing to DB...')
    db = SessionLocal()
    ev = EventORM(
        event_id=enriched.event_id,
        ts=enriched.ts,
        source_type='linux_auth',
        host=enriched.host,
        src_ip=enriched.src_ip,
        user=enriched.user,
        action=enriched.action,
        outcome='failure',
        raw=raw,
        raw_hash='test-hash-1',
    )
    db.add(ev)
    db.commit()
    db.close()
    print('DB committed successfully!')

    print('Publishing to event bus...')
    bus = get_event_bus()
    msg = StreamMessage(topic='events', event_type='event_ingested', payload={'event_id': enriched.event_id})
    await bus.publish('events', msg)
    print('Published to bus! Queue depth:', bus.get_queue_depth('events'))

asyncio.run(test())
print('All complete!')
