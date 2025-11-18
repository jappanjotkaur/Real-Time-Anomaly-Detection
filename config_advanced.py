"""
Advanced Configuration File
Configuration for all advanced features
"""

# Incident Response Configuration
INCIDENT_RESPONSE_CONFIG = {
    'auto_block': False,  # Set to True to enable automatic IP blocking (requires admin)
    'auto_throttle': True,  # Enable automatic rate limiting
    'block_duration': 3600,  # Duration to block IPs in seconds (1 hour)
    'throttle_threshold': 100,  # Packets per second threshold
    'whitelist_ips': [
        '127.0.0.1',
        '::1'
        # Add your trusted IPs here
    ]
}

# Zero-Day Detector Configuration
ZERO_DAY_DETECTOR_CONFIG = {
    'graph_window': 300,  # Time window in seconds for building network graphs
    'anomaly_threshold': 0.7  # Threshold for zero-day detection (0-1)
}

# Alerting System Configuration
ALERTING_CONFIG = {
    'email': {
        'enabled': False,  # Set to True to enable email alerts
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'username': 'your_email@gmail.com',
        'password': 'your_app_password',  # Use app password for Gmail
        'recipients': ['admin@yourdomain.com']
    },
    'slack': {
        'enabled': False,  # Set to True to enable Slack alerts
        'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
        'channel': '#security-alerts'
    },
    'telegram': {
        'enabled': False,  # Set to True to enable Telegram alerts
        'bot_token': 'YOUR_BOT_TOKEN',
        'chat_id': 'YOUR_CHAT_ID'
    },
    'webhook': {
        'enabled': False,  # Set to True to enable webhook alerts
        'url': 'https://your-webhook-endpoint.com/alerts',
        'headers': {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer YOUR_TOKEN'
        }
    }
}

# Threat Intelligence Configuration
THREAT_INTEL_CONFIG = {
    'cache_dir': 'threat_intel_cache',
    'update_on_startup': True,  # Update feeds when system starts
    'update_interval': 3600  # Update interval in seconds
}

# Continuous Learning Configuration
CONTINUOUS_LEARNING_CONFIG = {
    'enabled': True,
    'model_path': './model/continuous_model.pkl',
    'retrain_interval': 3600,  # Retrain every hour
    'min_samples': 1000  # Minimum samples required for retraining
}

# Advanced Features Configuration
ADVANCED_CONFIG = {
    'incident_response': INCIDENT_RESPONSE_CONFIG,
    'zero_day_detector': ZERO_DAY_DETECTOR_CONFIG,
    'alerting': ALERTING_CONFIG,
    'threat_intel': THREAT_INTEL_CONFIG,
    'continuous_learning': CONTINUOUS_LEARNING_CONFIG
}

