"""
Continuous Learning Pipeline
Automatically retrains ML models with new data
"""

import numpy as np
import joblib
import os
import time
from datetime import datetime, timedelta
from collections import deque
from typing import Dict, List, Optional
import threading
import json

try:
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class ContinuousLearningPipeline:
    """Continuous learning pipeline for automatic model retraining"""
    
    def __init__(self, model_path: str = './model/continuous_model.pkl',
                 retrain_interval: int = 3600, min_samples: int = 1000,
                 validation_split: float = 0.2):
        """
        Args:
            model_path: Path to save/load model
            retrain_interval: Time in seconds between retraining attempts
            min_samples: Minimum number of samples required for retraining
            validation_split: Fraction of data to use for validation
        """
        self.model_path = model_path
        self.retrain_interval = retrain_interval
        self.min_samples = min_samples
        self.validation_split = validation_split
        
        # Data storage
        self.feature_buffer = deque(maxlen=50000)  # Store up to 50k samples
        self.label_buffer = deque(maxlen=50000)
        self.timestamp_buffer = deque(maxlen=50000)
        
        # Model and scaler
        self.model = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        
        # Training history
        self.training_history = deque(maxlen=100)
        self.last_training_time = 0
        
        # Statistics
        self.stats = {
            'total_samples': 0,
            'training_count': 0,
            'last_training_time': None,
            'model_accuracy': None,
            'model_version': 0
        }
        
        # Load existing model if available
        self._load_model()
        
        # Start background retraining thread
        self.retraining_thread = None
        self.stop_retraining = False
    
    def add_sample(self, features: List[float], label: int, timestamp: float = None):
        """
        Add a new training sample
        Args:
            features: Feature vector
            label: Label (1 = normal, -1 = anomaly)
            timestamp: Sample timestamp (default: current time)
        """
        if timestamp is None:
            timestamp = time.time()
        
        self.feature_buffer.append(features)
        self.label_buffer.append(label)
        self.timestamp_buffer.append(timestamp)
        self.stats['total_samples'] += 1
        
        # Check if retraining is needed
        if len(self.feature_buffer) >= self.min_samples:
            if time.time() - self.last_training_time >= self.retrain_interval:
                self._trigger_retraining()
    
    def _trigger_retraining(self):
        """Trigger model retraining in background"""
        if self.retraining_thread is None or not self.retraining_thread.is_alive():
            self.retraining_thread = threading.Thread(target=self._retrain_model, daemon=True)
            self.retraining_thread.start()
    
    def _retrain_model(self):
        """Retrain the model with accumulated data"""
        if not SKLEARN_AVAILABLE:
            print("[!] Scikit-learn not available for retraining")
            return
        
        if len(self.feature_buffer) < self.min_samples:
            return
        
        try:
            print(f"[+] Starting model retraining with {len(self.feature_buffer)} samples...")
            
            # Convert to numpy arrays
            X = np.array(list(self.feature_buffer))
            y = np.array(list(self.label_buffer))
            
            # Split data
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=self.validation_split, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_val_scaled = self.scaler.transform(X_val)
            
            # Train model (using Isolation Forest as example)
            from sklearn.ensemble import IsolationForest
            
            # Calculate contamination rate from labels
            contamination = np.sum(y == -1) / len(y) if len(y) > 0 else 0.05
            contamination = max(0.01, min(0.5, contamination))  # Clamp between 1% and 50%
            
            self.model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
            
            # Train
            self.model.fit(X_train_scaled)
            
            # Evaluate
            train_score = self.model.score_samples(X_train_scaled)
            val_score = self.model.score_samples(X_val_scaled)
            
            train_accuracy = np.mean(train_score)
            val_accuracy = np.mean(val_score)
            
            # Save model
            self._save_model()
            
            # Update statistics
            self.stats['training_count'] += 1
            self.stats['last_training_time'] = time.time()
            self.stats['model_accuracy'] = float(val_accuracy)
            self.stats['model_version'] += 1
            
            # Record training history
            training_record = {
                'timestamp': time.time(),
                'samples': len(self.feature_buffer),
                'train_samples': len(X_train),
                'val_samples': len(X_val),
                'train_accuracy': float(train_accuracy),
                'val_accuracy': float(val_accuracy),
                'contamination': contamination,
                'model_version': self.stats['model_version']
            }
            self.training_history.append(training_record)
            
            self.last_training_time = time.time()
            
            print(f"[+] Model retraining complete!")
            print(f"    - Samples: {len(self.feature_buffer)}")
            print(f"    - Validation accuracy: {val_accuracy:.4f}")
            print(f"    - Model version: {self.stats['model_version']}")
            
        except Exception as e:
            print(f"[!] Error during model retraining: {e}")
            import traceback
            traceback.print_exc()
    
    def predict(self, features: List[float]) -> tuple:
        """
        Predict anomaly using current model
        Returns:
            (is_anomaly, score)
        """
        if self.model is None or self.scaler is None:
            return 0, 0.0
        
        try:
            X = np.array([features])
            X_scaled = self.scaler.transform(X)
            
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.score_samples(X_scaled)[0]
            
            return prediction, float(score)
        except Exception as e:
            print(f"[!] Error in prediction: {e}")
            return 0, 0.0
    
    def _save_model(self):
        """Save model and scaler"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'stats': self.stats,
                'training_history': list(self.training_history),
                'saved_at': time.time()
            }
            
            joblib.dump(model_data, self.model_path)
            
            # Also save metadata
            metadata_path = self.model_path.replace('.pkl', '_metadata.json')
            metadata = {
                'model_version': self.stats['model_version'],
                'last_training_time': self.stats['last_training_time'],
                'model_accuracy': self.stats['model_accuracy'],
                'total_samples': self.stats['total_samples'],
                'training_count': self.stats['training_count']
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            print(f"[!] Error saving model: {e}")
    
    def _load_model(self):
        """Load existing model"""
        if os.path.exists(self.model_path):
            try:
                model_data = joblib.load(self.model_path)
                self.model = model_data.get('model')
                self.scaler = model_data.get('scaler')
                
                if 'stats' in model_data:
                    self.stats.update(model_data['stats'])
                
                if 'training_history' in model_data:
                    self.training_history = deque(model_data['training_history'], maxlen=100)
                
                self.last_training_time = self.stats.get('last_training_time', 0)
                
                print(f"[+] Loaded continuous learning model (version {self.stats.get('model_version', 0)})")
            except Exception as e:
                print(f"[!] Error loading model: {e}")
    
    def get_statistics(self) -> Dict:
        """Get pipeline statistics"""
        return {
            **self.stats,
            'buffer_size': len(self.feature_buffer),
            'ready_for_training': len(self.feature_buffer) >= self.min_samples,
            'time_since_training': time.time() - self.last_training_time if self.last_training_time > 0 else 0,
            'training_history_count': len(self.training_history)
        }
    
    def get_training_history(self, limit: int = 10) -> List[Dict]:
        """Get recent training history"""
        return list(self.training_history)[-limit:]
    
    def start_continuous_retraining(self):
        """Start continuous retraining in background"""
        self.stop_retraining = False
        
        def retrain_loop():
            while not self.stop_retraining:
                time.sleep(self.retrain_interval)
                if len(self.feature_buffer) >= self.min_samples:
                    self._retrain_model()
        
        thread = threading.Thread(target=retrain_loop, daemon=True)
        thread.start()
        return thread
    
    def stop_continuous_retraining(self):
        """Stop continuous retraining"""
        self.stop_retraining = True

