"""
Advanced ML Models for Network Anomaly Detection
Includes Autoencoder, LSTM, and Ensemble models
"""

import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.ensemble import IsolationForest
from collections import deque
import os

try:
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("[!] TensorFlow not available. Advanced models will use scikit-learn fallbacks.")


class AutoencoderAnomalyDetector:
    """Autoencoder-based anomaly detector for deep learning anomaly detection"""
    
    def __init__(self, input_dim=8, encoding_dim=3, epochs=50, batch_size=32):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.scaler = MinMaxScaler()
        self.model = None
        self.is_trained = False
        self.threshold = 0.1
        
    def build_model(self):
        """Build autoencoder model"""
        if not TENSORFLOW_AVAILABLE:
            return None
            
        input_layer = layers.Input(shape=(self.input_dim,))
        encoded = layers.Dense(16, activation='relu')(input_layer)
        encoded = layers.Dense(self.encoding_dim, activation='relu')(encoded)
        decoded = layers.Dense(16, activation='relu')(encoded)
        decoded = layers.Dense(self.input_dim, activation='sigmoid')(decoded)
        
        autoencoder = keras.Model(input_layer, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        return autoencoder
    
    def fit(self, X):
        """Train the autoencoder"""
        if not TENSORFLOW_AVAILABLE or len(X) < 100:
            return False
            
        try:
            # Scale data
            X_scaled = self.scaler.fit_transform(X)
            
            # Build model if not exists
            if self.model is None:
                self.model = self.build_model()
                if self.model is None:
                    return False
            
            # Train model
            self.model.fit(
                X_scaled, X_scaled,
                epochs=self.epochs,
                batch_size=self.batch_size,
                verbose=0,
                shuffle=True
            )
            
            # Calculate reconstruction threshold
            reconstructions = self.model.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
            self.threshold = np.percentile(mse, 95)  # 95th percentile as threshold
            
            self.is_trained = True
            return True
        except Exception as e:
            print(f"[!] Error training autoencoder: {e}")
            return False
    
    def predict(self, X):
        """Predict anomalies"""
        if not self.is_trained or self.model is None:
            return 0, 0.0
            
        try:
            X_scaled = self.scaler.transform([X])
            reconstruction = self.model.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - reconstruction, 2))
            
            # Negative score means anomaly (similar to Isolation Forest)
            is_anomaly = -1 if mse > self.threshold else 1
            score = -mse  # Negative because higher MSE = more anomalous
            
            return is_anomaly, score
        except Exception as e:
            return 0, 0.0
    
    def save_model(self, filepath):
        """Save model"""
        if self.model and TENSORFLOW_AVAILABLE:
            try:
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                self.model.save(filepath.replace('.pkl', '_autoencoder.h5'))
                joblib.dump({
                    'scaler': self.scaler,
                    'threshold': self.threshold,
                    'input_dim': self.input_dim,
                    'encoding_dim': self.encoding_dim
                }, filepath)
                return True
            except Exception as e:
                print(f"[!] Error saving autoencoder: {e}")
        return False
    
    def load_model(self, filepath):
        """Load model"""
        if not TENSORFLOW_AVAILABLE:
            return False
        try:
            data = joblib.load(filepath)
            self.scaler = data['scaler']
            self.threshold = data['threshold']
            self.input_dim = data['input_dim']
            self.encoding_dim = data['encoding_dim']
            self.model = keras.models.load_model(filepath.replace('.pkl', '_autoencoder.h5'))
            self.is_trained = True
            return True
        except Exception as e:
            print(f"[!] Error loading autoencoder: {e}")
            return False


class LSTMAnalyzer:
    """LSTM-based time-series analyzer for sequential pattern detection"""
    
    def __init__(self, sequence_length=10, features=8, hidden_units=32):
        self.sequence_length = sequence_length
        self.features = features
        self.hidden_units = hidden_units
        self.scaler = StandardScaler()
        self.model = None
        self.is_trained = False
        self.sequence_buffer = deque(maxlen=sequence_length)
        
    def build_model(self):
        """Build LSTM model"""
        if not TENSORFLOW_AVAILABLE:
            return None
            
        model = keras.Sequential([
            layers.LSTM(self.hidden_units, return_sequences=True, input_shape=(self.sequence_length, self.features)),
            layers.LSTM(self.hidden_units, return_sequences=False),
            layers.Dense(self.features)
        ])
        model.compile(optimizer='adam', loss='mse')
        return model
    
    def fit(self, sequences):
        """Train LSTM on sequences"""
        if not TENSORFLOW_AVAILABLE or len(sequences) < self.sequence_length * 2:
            return False
            
        try:
            # Prepare sequences
            X = []
            y = []
            for i in range(len(sequences) - self.sequence_length):
                X.append(sequences[i:i+self.sequence_length])
                y.append(sequences[i+self.sequence_length])
            
            if len(X) < 10:
                return False
                
            X = np.array(X)
            y = np.array(y)
            
            # Scale data
            X_reshaped = X.reshape(-1, self.features)
            X_scaled = self.scaler.fit_transform(X_reshaped)
            X_scaled = X_scaled.reshape(X.shape)
            
            y_scaled = self.scaler.transform(y)
            
            # Build and train model
            if self.model is None:
                self.model = self.build_model()
                if self.model is None:
                    return False
            
            self.model.fit(
                X_scaled, y_scaled,
                epochs=20,
                batch_size=16,
                verbose=0,
                shuffle=True
            )
            
            self.is_trained = True
            return True
        except Exception as e:
            print(f"[!] Error training LSTM: {e}")
            return False
    
    def add_feature(self, features):
        """Add feature vector to sequence buffer"""
        self.sequence_buffer.append(features)
    
    def predict_deviation(self):
        """Predict if current sequence deviates from learned patterns"""
        if not self.is_trained or len(self.sequence_buffer) < self.sequence_length:
            return 0, 0.0
            
        try:
            sequence = np.array(list(self.sequence_buffer))
            sequence_reshaped = sequence.reshape(1, self.sequence_length, self.features)
            sequence_scaled = self.scaler.transform(sequence_reshaped.reshape(-1, self.features))
            sequence_scaled = sequence_scaled.reshape(sequence_reshaped.shape)
            
            prediction = self.model.predict(sequence_scaled, verbose=0)
            actual = sequence_scaled[0, -1, :]
            
            mse = np.mean(np.power(prediction[0] - actual, 2))
            
            # Higher MSE = more anomalous
            is_anomaly = -1 if mse > 0.5 else 1
            score = -mse
            
            return is_anomaly, score
        except Exception as e:
            return 0, 0.0


class EnsembleAnomalyDetector:
    """Ensemble of multiple anomaly detection models"""
    
    def __init__(self, model_path=None):
        self.isolation_forest = IsolationForest(contamination=0.05, random_state=42)
        self.autoencoder = AutoencoderAnomalyDetector()
        self.lstm = LSTMAnalyzer()
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = model_path or "./model/ensemble_model.pkl"
        
        # Weights for ensemble voting
        self.weights = {
            'isolation_forest': 0.4,
            'autoencoder': 0.35,
            'lstm': 0.25
        }
        
    def fit(self, feature_vectors):
        """Train all models"""
        if len(feature_vectors) < 100:
            return False
            
        try:
            X = np.array(feature_vectors)
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.isolation_forest.fit(X_scaled)
            
            # Train Autoencoder
            self.autoencoder.fit(X)
            
            # Train LSTM (requires sequences)
            if len(X) >= self.lstm.sequence_length * 2:
                sequences = [X_scaled[i:i+self.lstm.sequence_length+1] 
                           for i in range(len(X_scaled) - self.lstm.sequence_length)]
                if sequences:
                    self.lstm.fit(X)
            
            self.is_trained = True
            return True
        except Exception as e:
            print(f"[!] Error training ensemble: {e}")
            return False
    
    def predict(self, feature_vector):
        """Predict using ensemble voting"""
        if not self.is_trained:
            return 0, 0.0
        
        try:
            X_scaled = self.scaler.transform([feature_vector])
            
            # Get predictions from all models
            predictions = []
            scores = []
            
            # Isolation Forest
            if_pred = self.isolation_forest.predict(X_scaled)[0]
            if_score = self.isolation_forest.decision_function(X_scaled)[0]
            predictions.append(if_pred * self.weights['isolation_forest'])
            scores.append(if_score * self.weights['isolation_forest'])
            
            # Autoencoder
            ae_pred, ae_score = self.autoencoder.predict(feature_vector)
            if ae_pred != 0:
                predictions.append(ae_pred * self.weights['autoencoder'])
                scores.append(ae_score * self.weights['autoencoder'])
            
            # LSTM (requires sequence buffer)
            self.lstm.add_feature(X_scaled[0])
            lstm_pred, lstm_score = self.lstm.predict_deviation()
            if lstm_pred != 0:
                predictions.append(lstm_pred * self.weights['lstm'])
                scores.append(lstm_score * self.weights['lstm'])
            
            # Ensemble vote (weighted average)
            if predictions:
                weighted_pred = sum(predictions)
                weighted_score = sum(scores)
                
                # Anomaly if weighted prediction < 0
                is_anomaly = -1 if weighted_pred < -0.3 else 1
                
                return is_anomaly, weighted_score
            else:
                # Fallback to Isolation Forest only
                return if_pred, if_score
                
        except Exception as e:
            print(f"[!] Error in ensemble prediction: {e}")
            return 0, 0.0
    
    def save_model(self, filepath=None):
        """Save all models"""
        filepath = filepath or self.model_path
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Save autoencoder separately
            self.autoencoder.save_model(filepath.replace('.pkl', '_ae.pkl'))
            
            # Save other components
            joblib.dump({
                'isolation_forest': self.isolation_forest,
                'scaler': self.scaler,
                'weights': self.weights,
                'lstm_config': {
                    'sequence_length': self.lstm.sequence_length,
                    'features': self.lstm.features,
                    'hidden_units': self.lstm.hidden_units
                }
            }, filepath)
            
            return True
        except Exception as e:
            print(f"[!] Error saving ensemble: {e}")
            return False
    
    def load_model(self, filepath=None):
        """Load all models"""
        filepath = filepath or self.model_path
        try:
            if os.path.exists(filepath):
                data = joblib.load(filepath)
                self.isolation_forest = data['isolation_forest']
                self.scaler = data['scaler']
                self.weights = data.get('weights', self.weights)
                
                # Load autoencoder
                self.autoencoder.load_model(filepath.replace('.pkl', '_ae.pkl'))
                
                # Reinitialize LSTM with saved config
                if 'lstm_config' in data:
                    config = data['lstm_config']
                    self.lstm = LSTMAnalyzer(
                        sequence_length=config['sequence_length'],
                        features=config['features'],
                        hidden_units=config['hidden_units']
                    )
                
                self.is_trained = True
                return True
        except Exception as e:
            print(f"[!] Error loading ensemble: {e}")
        return False

