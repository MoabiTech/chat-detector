# Logo Detection Module
# Uses perceptual hashing (pHash) to detect copied/altered brand logos

import os
import io
from typing import List, Dict, Any
from PIL import Image
import imagehash

class LogoDetector:
    def __init__(self, logo_dir="logos"):
        self.logo_dir = logo_dir
        self.logo_hashes = {}
        self.load_logos()
    
    def load_logos(self):
        if not os.path.exists(self.logo_dir):
            return
        for fname in os.listdir(self.logo_dir):
            if fname.lower().endswith(('.png', '.jpg', '.jpeg', '.webp')):
                try:
                    path = os.path.join(self.logo_dir, fname)
                    img = Image.open(path)
                    phash = imagehash.phash(img)
                    self.logo_hashes[os.path.splitext(fname)[0]] = str(phash)
                except Exception as e:
                    print(f"Error loading logo {fname}: {e}")
    
    def detect(self, image_data: bytes, threshold: int = 10) -> List[Dict[str, Any]]:
        results = []
        try:
            img = Image.open(io.BytesIO(image_data))
            img_phash = imagehash.phash(img)
            for brand, logo_hash_str in self.logo_hashes.items():
                try:
                    logo_hash = imagehash.hex_to_hash(logo_hash_str)
                    diff = img_phash - logo_hash
                    if diff <= threshold:
                        results.append({
                            "brand": brand,
                            "similarity_score": max(0, 100 - (diff * 5)),
                            "hamming_distance": diff,
                            "detection_type": "copied/altered_logo"
                        })
                except:
                    continue
            results.sort(key=lambda x: x['hamming_distance'])
        except Exception as e:
            return [{"error": str(e)}]
        return results
