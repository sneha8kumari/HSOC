import asyncio.windows_events
import traceback

print("Trying asyncio.windows_events.ProactorEventLoop()...", flush=True)
try:
    loop = asyncio.windows_events.ProactorEventLoop()
    print("Loop created!", flush=True)
    loop.close()
except Exception as e:
    traceback.print_exc()

print("Trying asyncio.windows_events.SelectorEventLoop()...", flush=True)
try:
    loop2 = asyncio.windows_events.SelectorEventLoop()
    print("SelectorLoop created!", flush=True)
    loop2.close()
except Exception as e:
    traceback.print_exc()
print("Finished trace!", flush=True)
