import asyncio
async def dummy():
    print("Dummy running!", flush=True)

print("Starting dummy...", flush=True)
asyncio.run(dummy())
print("Dummy finished!", flush=True)
