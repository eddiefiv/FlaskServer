import random
import queue

from time import perf_counter

class EnqueueTimeoutException(Exception):
    ...

class QueueFullException(Exception):
    ...

class QueueEmptyException(Exception):
    ...

class FifoQueue[T]:
    items: list[T] = []

    def __init__(self, maxsize: int):
        self.maxsize = maxsize

    @property
    def empty(self) -> bool:
        return len(self.items) == 0

    @property
    def full(self) -> bool:
        return len(self.items) == self.maxsize

    def enqueue(self, item: T, block: bool = True, timeout: float = 5000) -> None:
        if block:
            start = perf_counter()
            while True:
                if not self.full:
                    self.items.append(item)
                    break
                end = perf_counter()
                elapsed = (end * 1000) - (start * 1000)
                if elapsed >= timeout:
                    raise EnqueueTimeoutException(f"Enqueue timed out at {elapsed}ms before item {item} could be added")
            return
        if self.full:
            raise QueueFullException(f"Queue full, cannot enqueue item {item}")
        self.items.append(item)

    def dequeue(self) -> T:
        if self.empty:
            raise QueueEmptyException("Queue empty, no items to dequeue")
        return self.items.pop(0)

q = FifoQueue[int](5)

for item in [random.randint(0, 100) for _ in range(9)]:
    try:
        q.enqueue(item, block = False)
    except QueueFullException as e:
        print(f"Queue full: {str(e)}")
        break

while not q.empty:
    print(f"Dequeuing item: {q.dequeue()}")