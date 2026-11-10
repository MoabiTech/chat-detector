# Model Framework and Integrations
# Structure for integrating trained deepfake/phishing models

import json
import os
from datetime import datetime

class ModelRegistry:
    def __init__(self, config_path="models/model_config.json"):
        self.config_path = config_path
        self.models = self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return self.get_default_config()
    
    def get_default_config(self):
        config = {
            "phishing_text_model": {
                "name": "rule-based-hybrid",
                "version": "1.0-prototype",
                "type": "rule-based",
                "status": "active",
                "source": "local_rules",
                "license": "MIT",
                "inputs": ["text"],
                "trained": False,
                "description": "Transparent rule-based classifier with URL/IP/punycode detection"
            },
            "image_deepfake_model": {
                "name": "not_configured",
                "version": "N/A",
                "status": "not_configured",
                "inputs": ["image"],
                "trained": False,
                "description": "Requires integration of validated model (e.g., from DeepfakeBench)"
            },
            "video_deepfake_model": {
                "name": "not_configured", 
                "version": "N/A",
                "status": "not_configured",
                "inputs": ["video"],
                "trained": False,
                "description": "Frame-level analysis pending model integration"
            },
            "audio_deepfake_model": {
                "name": "not_configured",
                "version": "N/A",
                "status": "not_configured",
                "inputs": ["audio"],
                "trained": False,
                "description": "Synthetic speech detection pending integration (e.g., wav2vec-based)"
            }
        }
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
        return config
    
    def get_model_info(self):
        return {
            "models": self.models,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
