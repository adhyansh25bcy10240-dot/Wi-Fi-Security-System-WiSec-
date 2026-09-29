import os
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

# Default Class Mapping
CLASS_NAMES = {
    0: "Normal",
    1: "PortScan",
    2: "DoS_SYN",
    3: "ARP_Spoofing"
}

# ============================================================
# 1. Dynamic PyTorch Model (Expandable Head for CIL)
# ============================================================
class WiSecThreatClassifier(nn.Module):
    def __init__(self, input_dim: int = 6, initial_classes: int = 2, hidden_dim: int = 32):
        super().__init__()
        self.feature_extractor = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU()
        )
        self.fc_out = nn.Linear(hidden_dim, initial_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        features = self.feature_extractor(x)
        return self.fc_out(features)

    def expand_classes(self, num_new_classes: int):
        """Dynamically expands output layer neurons without wiping existing weights."""
        old_out = self.fc_out.out_features
        new_out = old_out + num_new_classes
        in_dim = self.fc_out.in_features

        new_fc = nn.Linear(in_dim, new_out)
        with torch.no_grad():
            new_fc.weight[:old_out] = self.fc_out.weight
            new_fc.bias[:old_out] = self.fc_out.bias

        self.fc_out = new_fc


# ============================================================
# 2. Exemplar Replay Buffer (Prevents Catastrophic Forgetting)
# ============================================================
class ExemplarMemoryBuffer:
    def __init__(self, max_per_class: int = 50):
        self.max_per_class = max_per_class
        self.buffer = {}  # {class_id: [features]}

    def add_samples(self, features: np.ndarray, labels: np.ndarray):
        for c in np.unique(labels):
            c_feats = features[labels == c]
            if c not in self.buffer:
                self.buffer[c] = []
            self.buffer[c].extend(c_feats)
            if len(self.buffer[c]) > self.max_per_class:
                indices = np.random.choice(len(self.buffer[c]), self.max_per_class, replace=False)
                self.buffer[c] = [self.buffer[c][i] for i in indices]

    def get_replay_data(self):
        x, y = [], []
        for c, samples in self.buffer.items():
            for s in samples:
                x.append(s)
                y.append(c)
        if not x:
            return None, None
        return torch.tensor(np.array(x), dtype=torch.float32), torch.tensor(np.array(y), dtype=torch.long)


# ============================================================
# 3. Model Initializer & Training Runner
# ============================================================
def train_and_save_initial_model(save_path: str = "models/wisec_cil.pth"):
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    # Phase 1: Train on initial 2 classes (0: Normal, 1: PortScan)
    model = WiSecThreatClassifier(input_dim=6, initial_classes=2)
    memory = ExemplarMemoryBuffer(max_per_class=50)

    # Simulated synthetic feature vectors for baseline setup
    # Features: [pps, syn_ratio, unique_ports, avg_len, arp_rate, uncommon_ratio]
    np.random.seed(42)
    normal_x = np.random.normal(loc=[10, 0.05, 2, 500, 0.1, 0.05], scale=[2, 0.02, 1, 50, 0.05, 0.02], size=(200, 6))
    portscan_x = np.random.normal(loc=[150, 0.85, 40, 60, 0.1, 0.80], scale=[20, 0.05, 10, 10, 0.05, 0.05], size=(200, 6))
    
    X = np.vstack([normal_x, portscan_x])
    y = np.array([0]*200 + [1]*200)

    memory.add_samples(X, y)

    X_tensor = torch.tensor(X, dtype=torch.float32)
    y_tensor = torch.tensor(y, dtype=torch.long)

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.01)

    model.train()
    for epoch in range(50):
        optimizer.zero_grad()
        outputs = model(X_tensor)
        loss = criterion(outputs, y_tensor)
        loss.backward()
        optimizer.step()

    # Save model checkpoint along with class names
    torch.save({
        'model_state': model.state_dict(),
        'num_classes': 2,
        'class_names': CLASS_NAMES,
        'memory_buffer': memory.buffer
    }, save_path)
    print(f"[+] Initial CIL Model saved successfully to {save_path}")

    # ai/__init__.py

def get_classifier():
    from .train_cil import WiSecThreatClassifier, ExemplarMemoryBuffer
    return WiSecThreatClassifier, ExemplarMemoryBuffer

def get_predictor():
    from .predict import ThreatPredictor
    return ThreatPredictor

if __name__ == "__main__":
    train_and_save_initial_model()