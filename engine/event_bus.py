from queue import Queue

# Simple in-process event bus used for cross-module event passing
event_queue: Queue = Queue()


def push_event(event: dict) -> None:
    event_queue.put(event)


def get_event() -> dict:
    return event_queue.get()
