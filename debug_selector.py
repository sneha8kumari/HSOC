import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def dummy():
    print("Dummy running with SelectorEventLoop!", flush=True)

print("Starting dummy...", flush=True)
asyncio.run(dummy())
print("Dummy finished!", flush=True)
