import asyncio

async def dummy():
    print("Dummy running in manual loop!", flush=True)

print("Creating loop...", flush=True)
loop = asyncio.new_event_loop()
print("Running loop...", flush=True)
loop.run_until_complete(dummy())
print("Closing loop...", flush=True)
loop.close()
print("Success!", flush=True)
