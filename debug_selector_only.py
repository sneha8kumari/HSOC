import asyncio.windows_events
print("Creating SelectorEventLoop...", flush=True)
loop = asyncio.windows_events.SelectorEventLoop()
print("SelectorEventLoop created successfully!", flush=True)

async def test():
    print("Inside coroutine!", flush=True)
    return 42

res = loop.run_until_complete(test())
print("Result:", res, flush=True)
loop.close()
print("All done!", flush=True)
