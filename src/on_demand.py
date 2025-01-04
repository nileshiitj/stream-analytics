import numpy as np
from sklearn.cluster import KMeans

class OnDemandClassifier:
    def __init__(self, n_clusters=5):
        self.n_clusters = n_clusters
        
    def classify(self, data):
        """Classify data using K-means clustering"""
        # Reshape data for sklearn
        X = data.reshape(-1, 1)
        
        # Perform clustering
        kmeans = KMeans(n_clusters=self.n_clusters, random_state=42)
        return kmeans.fit_predict(X)
