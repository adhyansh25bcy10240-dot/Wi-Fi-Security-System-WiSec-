import os
import sqlite3
import torch
import torch.nn.functional as F
import numpy as np

# Fallback import to support both direct script execution and package imports
try:
    from .train_cil import WiSecThreatClassifier, CLASS_NAMES
except ImportError:
    from train_cil import WiSecThreatClassifier, CLASS_NAMES


class ThreatPredictor:
    def __init__(self, model_path: str = None, db_path: str = None):
        # Current file (ai/predict.py) ke reference se base directory calculate karein
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        self.model_path = model_path or os.path.join(base_dir, "models", "wisec_cil.pth")
        self.db_path = db_path or os.path.join(base_dir, "devices.db")

        self.model = None
        self.class_names = CLASS_NAMES

        # Default to a no-op normalization (mean=0, std=1) until load_model()
        # fills these in from the checkpoint. Keeps predict_vector() safe to
        # call even if load_model() bails early (e.g. file missing).
        self.feature_mean = torch.zeros(6, dtype=torch.float32)
        self.feature_std = torch.ones(6, dtype=torch.float32)

        self.load_model()

    def load_model(self):
        """Loads model weights and feature normalization stats securely."""
        if not os.path.exists(self.model_path):
            print(f"[!] Warning: Model file {self.model_path} not found.")
            return

        checkpoint = torch.load(self.model_path, weights_only=False)
        num_classes = checkpoint.get('num_classes', 2)
        self.class_names = checkpoint.get('class_names', CLASS_NAMES)

        self.model = WiSecThreatClassifier(input_dim=6, initial_classes=num_classes)
        self.model.load_state_dict(checkpoint['model_state'])
        self.model.eval()

        # --- Feature normalization (must match train_cil.py exactly) ---
        # Without this, raw features (which live on very different scales -
        # e.g. avg_len in the tens vs syn_ratio/arp_rate in 0-1) feed the
        # model unscaled and the large-magnitude features dominate the
        # prediction, drowning out the smaller ones. This was the root
        # cause behind predictions always landing on ARP_Spoofing
        # regardless of actual ARP activity.
        feature_mean = checkpoint.get('feature_mean')
        feature_std = checkpoint.get('feature_std')
        if feature_mean is not None and feature_std is not None:
            self.feature_mean = torch.tensor(feature_mean, dtype=torch.float32)
            self.feature_std = torch.tensor(feature_std, dtype=torch.float32)
        else:
            # Older checkpoint saved before normalization was added. Falls
            # back to a no-op so this doesn't crash, but predictions from
            # such a checkpoint should not be trusted - retrain with the
            # updated train_cil.py.
            print(
                "[!] Warning: checkpoint has no feature_mean/feature_std - "
                "predictions will be unnormalized and unreliable."
            )

    def predict_vector(self, feature_vector: list) -> tuple[str, float]:
        """Input: 6D feature list -> Returns: (Class Name, Confidence Score)"""
        if self.model is None:
            return "Normal", 0.0

        x = torch.tensor([feature_vector], dtype=torch.float32)

        # Apply the SAME z-score normalization the model was trained with.
        x = (x - self.feature_mean) / self.feature_std

        with torch.no_grad():
            logits = self.model(x)
            probs = F.softmax(logits, dim=1)
            conf, pred_idx = torch.max(probs, dim=1)

        class_id = pred_idx.item()
        confidence = conf.item()
        label = self.class_names.get(class_id, "Unknown")
        return label, confidence

    def update_database(self, ip: str, ai_status: str, threat_score: float):
        """Updates SQLite devices.db with prediction outputs."""
        if not os.path.exists(self.db_path):
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE devices 
            SET ai_status = ?, threat_score = ?
            WHERE ip = ?
        """, (ai_status, round(threat_score, 2), ip))
        conn.commit()
        conn.close()

    def analyze_and_update(self, ip: str, feature_vector: list):
        label, confidence = self.predict_vector(feature_vector)

        if label == "Normal":
            threat_score = 1.0 - confidence
        else:
            threat_score = confidence

        self.update_database(ip, label, threat_score)
        print(f"[AI Predict] IP: {ip} | Status: {label} | Score: {threat_score:.2f}")
        return label, threat_score


if __name__ == "__main__":
    predictor = ThreatPredictor()
    test_vec = [120.0, 0.9, 35.0, 54.0, 0.0, 0.8]
    predictor.analyze_and_update("192.168.1.130", test_vec)