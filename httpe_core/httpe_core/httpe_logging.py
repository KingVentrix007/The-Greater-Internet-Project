# logger.py
import asyncio
import datetime

log_queue = None  # Will be set by init_logger()

def init_logger():
    global log_queue
    print("Log queue is running")
    log_queue = asyncio.Queue()

async def log_writer(file_path="edoi_log.txt"):
    with open(file_path, "a", buffering=1) as f:
        while True:
            message = await log_queue.get()
            f.write(message + "\n")
            log_queue.task_done()

async def log(message):
    global log_queue

    # timestamp = datetime.datetime.now().isoformat()
    # log_entry = 
    await log_queue.put(message)

def sync_log(message):
    global log_queue
    try:
        if(log_queue == None):
            print("IDK why this is happening")
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(log_queue.put_nowait, message)
    except Exception:
        print("Runtime error")
        # No running loop in this thread — fallback to main loop
        loop = asyncio.get_event_loop()
        loop.call_soon_threadsafe(log_queue.put_nowait, message)