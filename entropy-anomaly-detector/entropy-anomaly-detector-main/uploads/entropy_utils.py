import math
from collections import Counter

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    byte_counts = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in byte_counts.values())
    return entropy
