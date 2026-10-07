import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

CLASS_NAMES = {
    0: "Normal",
    1: "PortScan",
    2: "DoS_SYN",
    3: "ARP_Spoofing"
}

# Feature vector order used EVERYWHERE in this project (train, predict,
# live sniffer, NetworkFeatureExtractor). If you ever add/remove a feature,
# update all four places together or everything silently breaks.
FEATURE_NAMES = ["pps", "syn_ratio", "unique_ports", "avg_len", "arp_rate", "uncommon_ratio"]


class WiSecThreatClassifier(nn.Module):
    def __init__(self, input_dim: int = 6, initial_classes: int = 2, hidden_dim: int = 64):
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
        old_out = self.fc_out.out_features
        new_out = old_out + num_new_classes
        in_dim = self.fc_out.in_features

        new_fc = nn.Linear(in_dim, new_out)
        with torch.no_grad():
            new_fc.weight[:old_out] = self.fc_out.weight
            new_fc.bias[:old_out] = self.fc_out.bias

        self.fc_out = new_fc


class ExemplarMemoryBuffer:
    def __init__(self, max_per_class: int = 100):
        self.max_per_class = max_per_class
        self.buffer = {}

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
# NEW: Feature normalization
# ============================================================
def compute_normalization_stats(X: np.ndarray):
    """
    Computes per-feature mean/std for z-score normalization.

    WHY THIS IS NEEDED:
    Our 6 raw features live on very different scales - e.g. avg_len can be
    in the tens-to-hundreds while syn_ratio/arp_rate/uncommon_ratio are
    always between 0 and 1. Fed into the network unscaled, the
    large-magnitude features (pps, avg_len) dominate the loss gradient and
    the small-magnitude features get effectively ignored. This is exactly
    what caused every traffic window to get classified as ARP_Spoofing
    regardless of actual ARP activity - the model was reacting to avg_len
    being "small" (which matches ARP_Spoofing's synthetic profile) and
    barely using arp_rate/syn_ratio at all.

    Normalizing puts every feature on a comparable scale so the model
    actually has to learn from all 6 of them, not just the ones with the
    biggest raw numbers.

    Returns (mean, std) as float32 numpy arrays, shape (6,). A small
    epsilon is added to std to avoid division by zero if any feature
    happens to be constant in the training data.
    """
    mean = X.mean(axis=0).astype(np.float32)
    std = (X.std(axis=0) + 1e-6).astype(np.float32)
    return mean, std


def normalize(X: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    """
    Applies z-score normalization using PRE-COMPUTED stats.

    IMPORTANT: the same mean/std must be used at training time (both
    phases) AND at inference time (live sniffer, predict.py). Recomputing
    stats per-phase, per-batch, or at inference would shift the input
    distribution relative to what the already-trained weights expect,
    which silently corrupts predictions without throwing any error.
    Compute once (on Phase 1 data, see train_and_save_cil_model below) and
    reuse everywhere after - including by saving it into the checkpoint.
    """
    return (X - mean) / std


def load_dataset_or_fallback(csv_path, expected_classes):
    """Loads CSV dataset if present, otherwise warns user."""
    if os.path.exists(csv_path):
        print(f"[+] Loading Dataset from CSV: {csv_path}")
        df = pd.read_csv(csv_path)
        # Assuming features: pps, syn_ratio, unique_ports, avg_len, arp_rate, uncommon_ratio, label
        X = df.iloc[:, :6].values.astype(np.float32)
        y = df.iloc[:, 6].values.astype(np.int64)
        return X, y
    else:
        print(f"[!] Warning: {csv_path} not found. Generating real-distribution synthetic fallback...")
        # NOTE: these synthetic distributions are PLACEHOLDERS ONLY, roughly
        # tuned for a small loopback/LAN test rig (small packets, avg_len in
        # the tens range rather than hundreds). They exist purely so the
        # pipeline runs end-to-end without real data.
        #
        # For results you can actually trust, replace this with real
        # models/dataset1.csv and models/dataset2.csv built from traffic you
        # actually captured (via NetworkFeatureExtractor or the live
        # sniffer's own feature extractor) and labeled correctly.
        X_list, y_list = [], []
        for c in expected_classes:
            if c == 0:  # Normal - low rate, low syn ratio, few ports, small packets
                data = np.random.normal(
                    loc=[10, 0.05, 2, 60, 0.01, 0.0],
                    scale=[2, 0.01, 1, 15, 0.005, 0.0],
                    size=(300, 6)
                )
            elif c == 1:  # PortScan - many unique ports hit, mostly bare SYNs
                data = np.random.normal(
                    loc=[80, 0.85, 45, 54, 0.0, 0.0],
                    scale=[10, 0.05, 5, 2, 0.0, 0.0],
                    size=(300, 6)
                )
            elif c == 2:  # DoS_SYN - very high packet rate, almost all SYN, single port
                data = np.random.normal(
                    loc=[350, 0.98, 1, 54, 0.0, 0.0],
                    scale=[30, 0.01, 0.0, 1, 0.0, 0.0],
                    size=(300, 6)
                )
            elif c == 3:  # ARP_Spoofing - defined by high arp_rate, not by TCP features
                data = np.random.normal(
                    loc=[30, 0.0, 0, 42, 0.90, 0.0],
                    scale=[5, 0.0, 0.0, 1, 0.02, 0.0],
                    size=(300, 6)
                )

            data = np.clip(data, 0, None)
            X_list.append(data)
            y_list.append(np.full(300, c))

        return np.vstack(X_list), np.concatenate(y_list)


def train_and_save_cil_model(save_path: str = "models/wisec_cil.pth"):
    os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
    np.random.seed(42)
    torch.manual_seed(42)

    # --------------------------------------------------------
    # Phase 1: Train Base Model (Class 0: Normal, Class 1: PortScan)
    # --------------------------------------------------------
    print("\n================ PHASE 1: Base CIL Training ================")
    X_p1, y_p1 = load_dataset_or_fallback("models/dataset1.csv", expected_classes=[0, 1])

    # Compute normalization stats ONCE, from Phase 1 data, and reuse them
    # for every phase after this AND at inference time. See
    # compute_normalization_stats()'s docstring for why this must not be
    # recomputed later (it would shift the input scale under weights that
    # were already trained on the Phase 1 scale).
    feature_mean, feature_std = compute_normalization_stats(X_p1)
    X_p1_norm = normalize(X_p1, feature_mean, feature_std)

    model = WiSecThreatClassifier(input_dim=6, initial_classes=2)
    memory = ExemplarMemoryBuffer(max_per_class=100)
    # Store RAW (unnormalized) features in the replay buffer. We normalize
    # right before feeding data into training instead - this way the buffer
    # always holds real-world values, easier to inspect/debug later.
    memory.add_samples(X_p1, y_p1)

    optimizer = optim.Adam(model.parameters(), lr=0.005)
    criterion = nn.CrossEntropyLoss()

    model.train()
    for epoch in range(100):
        optimizer.zero_grad()
        out = model(torch.tensor(X_p1_norm, dtype=torch.float32))
        loss = criterion(out, torch.tensor(y_p1, dtype=torch.long))
        loss.backward()
        optimizer.step()

    print("[+] Phase 1 Complete (Normal & PortScan trained).")

    # --------------------------------------------------------
    # Phase 2: Class-Incremental Learning Expansion (+ DoS_SYN & ARP_Spoofing)
    # --------------------------------------------------------
    print("\n================ PHASE 2: CIL Expansion (+ DoS_SYN & ARP_Spoofing) ================")
    model.expand_classes(num_new_classes=2)

    X_p2, y_p2 = load_dataset_or_fallback("models/dataset2.csv", expected_classes=[2, 3])

    # Reuse the SAME feature_mean/feature_std computed back in Phase 1 -
    # do NOT recompute from X_p2's own distribution, or the input scale
    # would shift under the already-trained Phase 1 weights.
    X_p2_norm = normalize(X_p2, feature_mean, feature_std)

    X_replay_raw, y_replay = memory.get_replay_data()
    if X_replay_raw is not None:
        X_replay_norm = normalize(X_replay_raw.numpy(), feature_mean, feature_std)
        X_combined = torch.cat([
            torch.tensor(X_p2_norm, dtype=torch.float32),
            torch.tensor(X_replay_norm, dtype=torch.float32)
        ], dim=0)
        y_combined = torch.cat([torch.tensor(y_p2, dtype=torch.long), y_replay], dim=0)
    else:
        # No replay samples yet (shouldn't normally happen since Phase 1
        # always populates the buffer first, but guarding against it anyway).
        X_combined = torch.tensor(X_p2_norm, dtype=torch.float32)
        y_combined = torch.tensor(y_p2, dtype=torch.long)

    memory.add_samples(X_p2, y_p2)  # store raw features, same convention as Phase 1

    optimizer = optim.Adam(model.parameters(), lr=0.002)

    for epoch in range(120):
        optimizer.zero_grad()
        out = model(X_combined)
        loss = criterion(out, y_combined)
        loss.backward()
        optimizer.step()

    torch.save({
        'model_state': model.state_dict(),
        'num_classes': 4,
        'class_names': CLASS_NAMES,
        'memory_buffer': memory.buffer,
        # Save normalization stats so every consumer of this checkpoint
        # (live sniffer's CILPredictor, predict.py's ThreatPredictor,
        # anything else loading this .pth) applies the EXACT same scaling
        # the model was actually trained with.
        'feature_mean': feature_mean,
        'feature_std': feature_std,
    }, save_path)

    print(f"\n[+] Real CIL Model saved successfully to: {save_path}")


if __name__ == "__main__":
    train_and_save_cil_model()