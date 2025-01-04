import numpy as np
from sklearn.preprocessing import StandardScaler

class VFDTClassifier:
    def __init__(self):
        self.ranges = [
            (0, 10),     # Very Low
            (10, 100),   # Low
            (100, 500),  # Medium
            (500, 1000), # High
            (1000, float('inf')) # Very High
        ]
        
    def classify(self, data):
        """Classify data into predefined ranges"""
        classes = np.zeros(len(data))
        for i, (low, high) in enumerate(self.ranges):
            mask = (data >= low) & (data < high)
            classes[mask] = i
        return classes
