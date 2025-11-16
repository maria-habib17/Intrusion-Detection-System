import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import joblib
import torch
import torch.nn as nn
from collections import deque
import warnings
warnings.filterwarnings('ignore')

class AIDetectionEngine:
    def __init__(self, config):
        self.config = config
        self.scaler = StandardScaler()
        self.models = {}
        self.behavior_profiles = {}
        self.setup_models()
        
    def setup_models(self):
        """Initialize multiple ML models for ensemble detection"""
        # Isolation Forest for anomaly detection
        self.models['isolation_forest'] = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        
        # Behavioral profiling model
        self.models['behavior_cluster'] = DBSCAN(eps=0.5, min_samples=5)
        
        # Simple Neural Network for advanced pattern recognition
        self.models['nn_model'] = SimpleNeuralNetwork()
        
        # Load pre-trained models if available
        try:
            self.models['isolation_forest'] = joblib.load('models/isolation_forest.pkl')
            print("✅ Loaded pre-trained AI models")
        except:
            print("🔄 Training new AI models with initial data")
            self.initialize_training()
    
    def initialize_training(self):
        """Generate initial training data based on known patterns"""
        # Simulate normal traffic patterns
        normal_patterns = self.generate_normal_traffic_patterns()
        self.models['isolation_forest'].fit(normal_patterns)
        joblib.dump(self.models['isolation_forest'], 'models/isolation_forest.pkl')
    
    def generate_normal_traffic_patterns(self):
        """Generate synthetic normal traffic patterns for training"""
        # Features: [packet_size, protocol, port, packets_per_second, connections_per_minute]
        normal_data = []
        
        # HTTP/HTTPS traffic
        for _ in range(1000):
            normal_data.append([1500, 6, 80, 2, 5])   # HTTP
            normal_data.append([1200, 6, 443, 1, 3])  # HTTPS
            normal_data.append([64, 1, 0, 1, 1])      # ICMP ping
            
        return np.array(normal_data)
    
    def extract_features(self, packet_data):
        """Extract features from packet data for ML analysis"""
        features = []
        
        # Basic packet features
        if hasattr(packet_data, 'size'):
            features.append(packet_data.size)
        else:
            features.append(0)
            
        # Protocol type (TCP=6, UDP=17, ICMP=1)
        features.append(self.get_protocol_code(packet_data))
        
        # Destination port (normalized)
        features.append(self.get_destination_port(packet_data))
        
        # Traffic rate features
        features.extend(self.get_traffic_rate_features(packet_data))
        
        return np.array(features).reshape(1, -1)
    
    def analyze_packet(self, packet_data, src_ip):
        """Analyze packet using ensemble AI methods"""
        features = self.extract_features(packet_data)
        
        # Get predictions from all models
        isolation_score = self.models['isolation_forest'].score_samples(features)[0]
        nn_confidence = self.models['nn_model'].predict(features)
        
        # Update behavioral profile
        self.update_behavioral_profile(src_ip, features)
        
        # Ensemble voting
        anomaly_confidence = (isolation_score + nn_confidence) / 2
        
        return {
            'is_anomaly': anomaly_confidence > self.config['detection_engines']['anomaly_based']['confidence_threshold'],
            'confidence': anomaly_confidence,
            'isolation_score': isolation_score,
            'behavior_deviation': self.calculate_behavior_deviation(src_ip, features)
        }
    
    def update_behavioral_profile(self, src_ip, features):
        """Update behavioral profile for IP address"""
        if src_ip not in self.behavior_profiles:
            self.behavior_profiles[src_ip] = {
                'packet_sizes': deque(maxlen=1000),
                'ports_accessed': set(),
                'protocols_used': set(),
                'traffic_patterns': deque(maxlen=500),
                'first_seen': pd.Timestamp.now(),
                'last_seen': pd.Timestamp.now()
            }
        
        profile = self.behavior_profiles[src_ip]
        profile['packet_sizes'].append(features[0][0])  # packet size
        profile['last_seen'] = pd.Timestamp.now()
        profile['traffic_patterns'].append(features[0])
    
    def calculate_behavior_deviation(self, src_ip, current_features):
        """Calculate how much current behavior deviates from historical profile"""
        if src_ip not in self.behavior_profiles:
            return 0.0  # No history yet
        
        profile = self.behavior_profiles[src_ip]
        if len(profile['traffic_patterns']) < 10:
            return 0.0  # Not enough history
        
        historical_data = np.array(list(profile['traffic_patterns']))
        current_data = current_features[0]
        
        # Calculate Euclidean distance from historical mean
        historical_mean = np.mean(historical_data, axis=0)
        deviation = np.linalg.norm(current_data - historical_mean)
        
        return deviation

class SimpleNeuralNetwork(nn.Module):
    def __init__(self, input_size=5, hidden_size=64, output_size=1):
        super(SimpleNeuralNetwork, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, hidden_size//2),
            nn.ReLU(),
            nn.Linear(hidden_size//2, output_size),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.network(x)
    
    def predict(self, x):
        with torch.no_grad():
            x_tensor = torch.FloatTensor(x)
            return self.network(x_tensor).item()