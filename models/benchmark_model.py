import json
import os
import sys
import time
from datetime import datetime
import numpy as np

# Add models/ directory to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))

if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from predict import ThreatPredictor


def run_empirical_benchmark():
    print("=" * 65)
    print("🔬 REAL PYTORCH CIL MODEL EVALUATION (AUTHENTIC INFERENCE)")
    print("=" * 65)

    predictor = ThreatPredictor()

    np.random.seed(42)
    test_dataset = []

    # Features: [pkts, syn_ratio, unique_ports, avg_pkt_size, rst_ratio, duration]

    # 1. Baseline Normal Traffic (25 samples)
    for _ in range(25):
        pkts = np.random.uniform(5.0, 45.0)
        syn = np.random.uniform(0.01, 0.15)
        ports = float(np.random.randint(1, 4))
        pkt_size = np.random.uniform(200, 1000)
        rst = np.random.uniform(0.0, 0.05)
        dur = 5.0
        test_dataset.append(([pkts, syn, ports, pkt_size, rst, dur], "Normal"))

    # 2. PortScan Traffic (25 samples)
    for _ in range(25):
        pkts = np.random.uniform(25.0, 90.0)
        syn = np.random.uniform(0.70, 0.98)
        ports = float(np.random.randint(12, 60))
        pkt_size = np.random.uniform(50, 90)
        rst = np.random.uniform(0.1, 0.6)
        dur = 5.0
        test_dataset.append(
            ([pkts, syn, ports, pkt_size, rst, dur], "PortScan")
        )

    # 3. DoS SYN Flood Traffic (25 samples)
    for _ in range(25):
        pkts = np.random.uniform(300.0, 1200.0)
        syn = np.random.uniform(0.85, 1.0)
        ports = float(np.random.randint(1, 3))
        pkt_size = np.random.uniform(40, 60)
        rst = np.random.uniform(0.0, 0.02)
        dur = 5.0
        test_dataset.append(([pkts, syn, ports, pkt_size, rst, dur], "DoS_SYN"))

    # 4. ARP Spoofing Traffic (25 samples)
    for _ in range(25):
        pkts = np.random.uniform(15.0, 50.0)
        syn = 0.0
        ports = 0.0
        pkt_size = np.random.uniform(42, 60)
        rst = 0.0
        dur = 5.0
        test_dataset.append(
            ([pkts, syn, ports, pkt_size, rst, dur], "ARP_Spoofing")
        )

    y_true = []
    y_pred = []
    confidences = []
    latencies = []

    print(
        f"[*] Running pure PyTorch inference across {len(test_dataset)} feature vectors...\n"
    )

    for features, true_label in test_dataset:
        start_t = time.perf_counter()

        pred_label, confidence = predictor.predict_vector(features)

        latency = (time.perf_counter() - start_t) * 1000  # ms

        latencies.append(latency)
        confidences.append(confidence * 100.0)  # Convert float to percentage
        y_true.append(true_label)
        y_pred.append(pred_label)

    classes = ["Normal", "PortScan", "DoS_SYN", "ARP_Spoofing"]

    print("-" * 65)
    print(
        f"{'Class':<15} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Samples'}"
    )
    print("-" * 65)

    metrics_summary = {}

    for cls in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p == cls)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != cls and p == cls)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p != cls)
        support = sum(1 for t in y_true if t == cls)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        metrics_summary[cls] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "sample_count": support,
        }

        print(
            f"{cls:<15} | {prec*100:8.2f}% | {rec*100:8.2f}% | {f1*100:8.2f}% | {support}"
        )

    total_acc = sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true)
    avg_lat = np.mean(latencies)
    avg_conf = np.mean(confidences)

    report_data = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "evaluation_type": "Pure PyTorch Neural Network Inference",
            "total_samples_evaluated": len(y_true),
        },
        "performance": {
            "overall_accuracy": round(total_acc * 100, 2),
            "avg_confidence_pct": round(avg_conf, 2),
            "avg_inference_latency_ms": round(avg_lat, 4),
        },
        "class_metrics": metrics_summary,
    }

    report_file = os.path.join(PROJECT_ROOT, "nids_benchmark_report.json")
    with open(report_file, "w") as f:
        json.dump(report_data, f, indent=4)

    print("-" * 65)
    print(f"\n📊 Total Accuracy: {total_acc*100:.2f}%")
    print(f"🎯 Average Model Confidence: {avg_conf:.2f}%")
    print(f"⚡ Average Latency per Sample: {avg_lat:.4f} ms")
    print(f"\n[+] Authentic JSON report saved to: {report_file}\n")


if __name__ == "__main__":
    run_empirical_benchmark()