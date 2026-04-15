# verdict_queue.py
from queue import Queue

# Global queue for attack verdicts (max 10,000 pending)
VERDICT_QUEUE = Queue(maxsize=10000)