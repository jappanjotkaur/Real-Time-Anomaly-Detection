"""
Evaluate multiple unsupervised anomaly detection algorithms on packet-level features.

This script builds a feature dataset from existing PCAP captures, trains several
unsupervised models (including innovative detectors), and reports standard metrics.

It intentionally keeps dependencies within the repository (TensorFlow optional) and
avoids pyod so it can run in the default environment.
"""

import argparse
import json
import math
import os
import random
from glob import glob

import dpkt
import numpy as np
from rich import box
from rich.console import Console
from rich.table import Table
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_recall_curve, roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KernelDensity, LocalOutlierFactor
from sklearn.svm import OneClassSVM

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Ensure repository root is on sys.path for imports like `models.*`
import sys
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import tensorflow as tf
    from tensorflow import keras
except Exception:  # pragma: no cover - tensorflow might be optional
    tf = None
    keras = None

from models.anomaly_detector import EnhancedAnomalyDetection
from utils.packet_parser import PacketParser


SEED = 42
RNG = np.random.default_rng(SEED)
random.seed(SEED)


class KernelDensityDetector:
    """Uses a KDE model to estimate density and flag low-density regions."""

    def __init__(self, bandwidth: float = 1.0):
        self.model = KernelDensity(bandwidth=bandwidth, kernel="gaussian")

    def fit(self, X: np.ndarray):
        self.model.fit(X)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        log_density = self.model.score_samples(X)
        return -log_density  # lower density => higher anomaly score


class AutoencoderDetector:
    """Lightweight feed-forward autoencoder for unsupervised detection."""

    def __init__(self, epochs: int = 30, batch_size: int = 64):
        if keras is None:
            raise RuntimeError("TensorFlow is not available. Install tensorflow to use AutoencoderDetector.")
        self.epochs = epochs
        self.batch_size = batch_size
        self.model = None

    def fit(self, X: np.ndarray):
        input_dim = X.shape[1]
        inputs = keras.layers.Input(shape=(input_dim,))
        x = keras.layers.Dense(input_dim * 2, activation="relu")(inputs)
        x = keras.layers.Dropout(0.2)(x)
        x = keras.layers.Dense(input_dim, activation="relu")(x)
        latent = keras.layers.Dense(max(2, input_dim // 2), activation="relu")(x)
        x = keras.layers.Dense(input_dim, activation="relu")(latent)
        outputs = keras.layers.Dense(input_dim, activation="linear")(x)

        self.model = keras.Model(inputs, outputs)
        self.model.compile(optimizer="adam", loss="mse")

        self.model.fit(
            X,
            X,
            epochs=self.epochs,
            batch_size=self.batch_size,
            shuffle=True,
            validation_split=0.1,
            verbose=0,
            callbacks=[
                keras.callbacks.EarlyStopping(
                    monitor="val_loss", patience=5, restore_best_weights=True
                )
            ],
        )
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        recon = self.model.predict(X, verbose=0)
        err = np.mean(np.square(X - recon), axis=1)
        return err


class HBOSDetector:
    """Histogram-Based Outlier Score (simple implementation)."""

    def __init__(self, bins: int = 20, clip: float = 1e-6):
        self.bins = bins
        self.clip = clip
        self.hist_edges_ = None
        self.hist_freq_ = None

    def fit(self, X: np.ndarray):
        n_features = X.shape[1]
        self.hist_edges_ = []
        self.hist_freq_ = []
        for j in range(n_features):
            hist, edges = np.histogram(X[:, j], bins=self.bins, density=True)
            self.hist_freq_.append(hist + self.clip)
            self.hist_edges_.append(edges)
        return self

    def _bin_density(self, values: np.ndarray, edges: np.ndarray, freqs: np.ndarray) -> np.ndarray:
        # Map values to bin densities; out-of-range use nearest bin density
        idx = np.digitize(values, edges) - 1
        idx = np.clip(idx, 0, len(freqs) - 1)
        return freqs[idx]

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        scores = np.zeros(X.shape[0], dtype=float)
        for j in range(X.shape[1]):
            dens = self._bin_density(X[:, j], self.hist_edges_[j], self.hist_freq_[j])
            scores += -np.log(dens)
        return scores


def load_features_from_pcaps(pcap_paths, max_packets=8000):
    parser = PacketParser()
    detector = EnhancedAnomalyDetection(model_path=None)
    features = []
    packet_counter = 0

    timestamp_offset = 0.0
    for path in pcap_paths:
        try:
            with open(path, "rb") as fh:
                reader = dpkt.pcap.Reader(fh)
                for timestamp, raw in reader:
                    packet_info = parser.parse_packet(raw)
                    if not packet_info:
                        continue
                    timestamp = float(timestamp) + timestamp_offset
                    feat_vector, _ = detector.extract_features(packet_info, timestamp)
                    if np.any(np.isnan(feat_vector)) or np.any(np.isinf(feat_vector)):
                        continue
                    features.append(feat_vector)
                    packet_counter += 1
                    if packet_counter >= max_packets:
                        return np.array(features)
            timestamp_offset += 10_000  # prevent overlapping timestamps across files
        except (OSError, dpkt.NeedData) as exc:
            print(f"[!] Skipping {path}: {exc}")
    return np.array(features)


def generate_synthetic_anomalies(normals: np.ndarray, ratio: float = 0.2) -> np.ndarray:
    n_normals, n_features = normals.shape
    n_anoms = max(1, int(n_normals * ratio))
    mean = normals.mean(axis=0)
    std = normals.std(axis=0) + 1e-6

    exaggerated = RNG.normal(loc=mean + 4 * std * RNG.choice([-1, 1], size=(n_anoms, n_features)),
                             scale=std * 3)
    shuffled = normals[RNG.integers(0, n_normals, size=n_anoms)].copy()
    RNG.shuffle(shuffled, axis=1)
    anomalies = 0.6 * exaggerated + 0.4 * shuffled
    return anomalies


def confusion_from_scores(scores: np.ndarray, y_true: np.ndarray, threshold: float):
    y_pred = (scores >= threshold).astype(int)
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    return tp, fp, tn, fn


def eval_metrics_from_scores(scores: np.ndarray, y_true: np.ndarray, contamination: float):
    threshold = np.percentile(scores, 100 * (1 - contamination))
    tp, fp, tn, fn = confusion_from_scores(scores, y_true, threshold)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    f1 = f1_score(y_true, (scores >= threshold).astype(int))
    # Alternative F-scores
    beta05 = 0.5
    f05 = (1 + beta05**2) * precision * recall / (beta05**2 * precision + recall) if (precision + recall) else 0.0
    beta2 = 2.0
    f2 = (1 + beta2**2) * precision * recall / (beta2**2 * precision + recall) if (precision + recall) else 0.0
    bal_acc = 0.5 * (recall + specificity)
    # Matthews correlation coefficient
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / denom) if denom else 0.0
    roc = roc_auc_score(y_true, scores)
    pr = average_precision_score(y_true, scores)
    precision_curve, recall_curve, _ = precision_recall_curve(y_true, scores)
    pr_curve = list(zip(precision_curve.tolist(), recall_curve.tolist()))
    return {
        "threshold": float(threshold),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "f05": f05,
        "f2": f2,
        "balanced_accuracy": bal_acc,
        "mcc": mcc,
        "roc_auc": roc,
        "pr_auc": pr,
        "precision_recall_curve": pr_curve,
    }


def evaluate_detector(name, detector, X_train, X_test, y_test, contamination):
    detector.fit(X_train)
    scores = detector.score_samples(X_test)
    metrics = eval_metrics_from_scores(scores, y_test, contamination)
    metrics.update({"name": name, "contamination": contamination, "scores": scores.tolist()})
    return metrics


def plot_roc_curves(results, y_test, output_dir):
    """Generate ROC curve comparison plot"""
    if not MATPLOTLIB_AVAILABLE:
        return
    
    plt.figure(figsize=(10, 8))
    for res in results:
        scores = np.array(res.get("scores", []))
        if len(scores) == len(y_test):
            fpr, tpr, _ = roc_curve(y_test, scores)
            auc = res.get("roc_auc", 0)
            plt.plot(fpr, tpr, label=f"{res['name']} (AUC={auc:.3f})", linewidth=2)
    
    plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier', linewidth=1)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('ROC Curves Comparison', fontsize=14, fontweight='bold')
    plt.legend(loc="lower right", fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    
    roc_path = os.path.join(output_dir, "roc_curves.png")
    plt.savefig(roc_path, dpi=300, bbox_inches='tight')
    plt.close()
    return roc_path


def plot_pr_curves(results, y_test, output_dir):
    """Generate Precision-Recall curve comparison plot"""
    if not MATPLOTLIB_AVAILABLE:
        return
    
    plt.figure(figsize=(10, 8))
    for res in results:
        scores = np.array(res.get("scores", []))
        if len(scores) == len(y_test):
            precision, recall, _ = precision_recall_curve(y_test, scores)
            pr_auc = res.get("pr_auc", 0)
            plt.plot(recall, precision, label=f"{res['name']} (AUC={pr_auc:.3f})", linewidth=2)
    
    baseline = np.sum(y_test) / len(y_test)
    plt.axhline(y=baseline, color='k', linestyle='--', label=f'Baseline ({baseline:.3f})', linewidth=1)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title('Precision-Recall Curves Comparison', fontsize=14, fontweight='bold')
    plt.legend(loc="lower left", fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    
    pr_path = os.path.join(output_dir, "pr_curves.png")
    plt.savefig(pr_path, dpi=300, bbox_inches='tight')
    plt.close()
    return pr_path


def plot_confusion_matrices(results, y_test, output_dir):
    """Generate confusion matrix heatmaps for all models"""
    if not MATPLOTLIB_AVAILABLE:
        return
    
    n_models = len(results)
    cols = 3
    rows = (n_models + cols - 1) // cols
    
    fig, axes = plt.subplots(rows, cols, figsize=(18, 5.5 * rows))
    if rows == 1:
        axes = axes.reshape(1, -1)
    axes = axes.flatten()
    
    for idx, res in enumerate(results):
        scores = np.array(res.get("scores", []))
        if len(scores) != len(y_test):
            continue
        
        threshold = res.get("threshold", np.percentile(scores, 95))
        y_pred = (scores >= threshold).astype(int)
        cm = confusion_matrix(y_test, y_pred)
        
        ax = axes[idx]
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax, cbar_kws={'shrink': 0.8})
        ax.set_title(f"{res['name']}\nF1={res.get('f1', 0):.3f}", fontsize=11, fontweight='bold')
        ax.set_xlabel('Predicted', fontsize=10)
        ax.set_ylabel('Actual', fontsize=10)
        ax.set_xticklabels(['Normal', 'Anomaly'])
        ax.set_yticklabels(['Normal', 'Anomaly'])
    
    # Hide unused subplots
    for idx in range(len(results), len(axes)):
        axes[idx].axis('off')
    
    plt.suptitle('Confusion Matrices by Model', fontsize=16, fontweight='bold', y=1.0)
    plt.tight_layout()
    
    cm_path = os.path.join(output_dir, "confusion_matrices.png")
    plt.savefig(cm_path, dpi=300, bbox_inches='tight')
    plt.close()
    return cm_path


def plot_anomaly_score_distributions(results, y_test, output_dir):
    """Plot anomaly score distributions for normal vs anomalous samples"""
    if not MATPLOTLIB_AVAILABLE:
        return
    
    n_models = len(results)
    cols = 3
    rows = (n_models + cols - 1) // cols
    
    fig, axes = plt.subplots(rows, cols, figsize=(15, 5 * rows))
    if rows == 1:
        axes = axes.reshape(1, -1)
    axes = axes.flatten()
    
    for idx, res in enumerate(results):
        scores = np.array(res.get("scores", []))
        if len(scores) != len(y_test):
            continue
        
        normal_scores = scores[y_test == 0]
        anomaly_scores = scores[y_test == 1]
        threshold = res.get("threshold", np.percentile(scores, 95))

        ax = axes[idx]
        
        # We'll determine a safe x-window first, then build capped bin edges inside it.
        ax.axvline(threshold, color='green', linestyle='--', linewidth=2, label='Threshold')

        # Focus view on central percentiles for readability
        low_clip = np.nanpercentile(scores, 0.5)
        high_clip = np.nanpercentile(scores, 99.5)
        display_min = np.nanmin([low_clip, threshold])
        display_max = np.nanmax([high_clip, threshold])
        if not np.isfinite(display_min) or not np.isfinite(display_max):
            display_min, display_max = np.nanmin(scores), np.nanmax(scores)

        if display_max <= display_min:
            span = max(1.0, abs(display_max) * 0.1)
            display_min -= span
            display_max += span

        # Decide whether to use a compressed (log1p) plotting scale for skewed scores
        p05 = np.nanpercentile(scores, 5)
        p50 = np.nanpercentile(scores, 50)
        p95 = np.nanpercentile(scores, 95)
        iqr_like = max(1e-9, p95 - p50)
        lower_spread = max(1e-9, p50 - p05)
        skew_metric = iqr_like / lower_spread
        use_log_compression = skew_metric > 50 or (np.nanmax(np.abs(scores)) / max(1e-9, np.nanmedian(np.abs(scores)))) > 1e3

        def signed_log1p(x: np.ndarray) -> np.ndarray:
            return np.sign(x) * np.log1p(np.abs(x))

        if use_log_compression:
            # Transform values only for visualization
            normal_plot = signed_log1p(normal_scores)
            anomaly_plot = signed_log1p(anomaly_scores)
            threshold_plot = float(signed_log1p(np.array([threshold]))[0])
            vis_min = float(signed_log1p(np.array([display_min]))[0])
            vis_max = float(signed_log1p(np.array([display_max]))[0])
            xlabel_suffix = " (log1p scale)"
        else:
            normal_plot = normal_scores
            anomaly_plot = anomaly_scores
            threshold_plot = threshold
            vis_min, vis_max = display_min, display_max
            xlabel_suffix = ""

        # Build capped number of bins within the visible window.
        approx_bins = int(max(20, min(80, np.cbrt(scores.size) * 4)))
        try:
            if use_log_compression:
                base_for_bins = np.concatenate([normal_plot, anomaly_plot])
            else:
                base_for_bins = scores
            fd_edges = np.histogram_bin_edges(base_for_bins, bins="fd")
            if len(fd_edges) > approx_bins or len(fd_edges) < 2 or not np.all(np.isfinite(fd_edges)):
                raise ValueError
            bin_edges = fd_edges[(fd_edges >= vis_min) & (fd_edges <= vis_max)]
            if len(bin_edges) < 2:
                raise ValueError
        except Exception:
            bin_edges = np.linspace(vis_min, vis_max, num=approx_bins)

        # Plot using the safe, capped bins
        ax.hist(normal_plot, bins=bin_edges, alpha=0.55, label='Normal', color='blue', density=True)
        ax.hist(anomaly_plot, bins=bin_edges, alpha=0.55, label='Anomaly', color='red', density=True)
        ax.axvline(threshold_plot, color='green', linestyle='--', linewidth=2, label='Threshold')

        clipped_low = int(np.sum(scores < display_min))
        clipped_high = int(np.sum(scores > display_max))

        ax.set_xlim(vis_min, vis_max)
        ax.ticklabel_format(style='sci', axis='x', scilimits=(-2, 3))

        if clipped_low or clipped_high:
            parts = []
            if clipped_low:
                parts.append(f"{clipped_low} low")
            if clipped_high:
                parts.append(f"{clipped_high} high")
            ax.text(
                0.02,
                0.95,
                f"Clipped: {', '.join(parts)}",
                transform=ax.transAxes,
                fontsize=8,
                verticalalignment='top',
                bbox=dict(boxstyle='round,pad=0.2', facecolor='white', alpha=0.6)
            )

        ax.set_title(f"{res['name']}", fontsize=11, fontweight='bold')
        ax.set_xlabel(f'Anomaly Score{xlabel_suffix}', fontsize=10)
        ax.set_ylabel('Density', fontsize=10)
        ax.legend(fontsize=8, loc='upper right', framealpha=0.8)
        ax.grid(True, alpha=0.3)
    
    # Hide unused subplots
    for idx in range(len(results), len(axes)):
        axes[idx].axis('off')
    
    plt.suptitle('Anomaly Score Distributions', fontsize=16, fontweight='bold', y=1.0)
    plt.tight_layout()
    
    dist_path = os.path.join(output_dir, "score_distributions.png")
    plt.savefig(dist_path, dpi=300, bbox_inches='tight')
    plt.close()
    return dist_path


def main():
    parser = argparse.ArgumentParser(description="Evaluate unsupervised anomaly detectors on captures")
    parser.add_argument("--captures", nargs="*", default=None,
                        help="Specific PCAP files to use. Defaults to all in captures/")
    parser.add_argument("--max-packets", type=int, default=8000,
                        help="Maximum packets to use for building the dataset")
    parser.add_argument("--anomaly-ratio", type=float, default=0.2,
                        help="Synthetic anomaly ratio for evaluation")
    parser.add_argument("--output", default="reports/anomaly_eval.json",
                        help="Where to store evaluation metrics (JSON)")
    args = parser.parse_args()

    if args.captures:
        pcap_files = args.captures
    else:
        pcap_files = sorted(glob(os.path.join("captures", "*.pcap")))

    if not pcap_files:
        raise SystemExit("No PCAP files found. Provide --captures or add files to captures/.")

    print(f"[+] Building dataset from {len(pcap_files)} PCAP files (limit {args.max_packets} packets)...")
    feature_matrix = load_features_from_pcaps(pcap_files, max_packets=args.max_packets)

    if feature_matrix.size == 0:
        raise SystemExit("Failed to extract features from captures.")

    print(f"[+] Extracted {len(feature_matrix)} packet feature vectors.")

    anomalies = generate_synthetic_anomalies(feature_matrix, ratio=args.anomaly_ratio)
    X = np.vstack([feature_matrix, anomalies])
    y = np.concatenate([np.zeros(len(feature_matrix), dtype=int), np.ones(len(anomalies), dtype=int)])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.35, stratify=y, random_state=SEED
    )

    # Use only normal samples for training detectors
    X_train_normals = X_train[y_train == 0]
    contamination = y_test.mean()

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_normals)
    X_test_scaled = scaler.transform(X_test)

    console = Console()
    results = []

    # Isolation Forest baseline
    iso = IsolationForest(contamination=contamination, random_state=SEED)
    iso.fit(X_train_scaled)
    iso_scores = -iso.decision_function(X_test_scaled)
    iso_threshold = np.percentile(iso_scores, 100 * (1 - contamination))
    iso_pred = (iso_scores >= iso_threshold).astype(int)
    iso_metrics = eval_metrics_from_scores(iso_scores, y_test, contamination)
    iso_metrics.update({"name": "IsolationForest", "contamination": contamination, "scores": iso_scores.tolist()})
    results.append(iso_metrics)

    # Kernel Density detector
    kde = KernelDensityDetector(bandwidth=1.0)
    kde_results = evaluate_detector(
        "KernelDensity",
        kde,
        X_train_scaled,
        X_test_scaled,
        y_test,
        contamination,
    )
    results.append(kde_results)

    # One-Class SVM (rbf kernel)
    ocsvm = OneClassSVM(kernel="rbf", gamma="scale", nu=min(0.5, max(0.01, contamination + 0.02)))
    ocsvm.fit(X_train_scaled)
    ocsvm_scores = -ocsvm.decision_function(X_test_scaled)
    ocsvm_metrics = eval_metrics_from_scores(ocsvm_scores, y_test, contamination)
    ocsvm_metrics.update({"name": "OneClassSVM", "contamination": contamination, "scores": ocsvm_scores.tolist()})
    results.append(ocsvm_metrics)

    # Local Outlier Factor (novelty mode)
    lof = LocalOutlierFactor(novelty=True, contamination=contamination)
    lof.fit(X_train_scaled)
    lof_scores = -lof.decision_function(X_test_scaled)
    lof_metrics = eval_metrics_from_scores(lof_scores, y_test, contamination)
    lof_metrics.update({"name": "LOF", "contamination": contamination, "scores": lof_scores.tolist()})
    results.append(lof_metrics)

    # HBOS
    hbos = HBOSDetector(bins=30)
    hbos_results = evaluate_detector("HBOS", hbos, X_train_scaled, X_test_scaled, y_test, contamination)
    results.append(hbos_results)

    # Autoencoder detector (optional)
    if keras is not None:
        ae = AutoencoderDetector(epochs=40, batch_size=64)
        ae_results = evaluate_detector(
            "Autoencoder",
            ae,
            X_train_scaled,
            X_test_scaled,
            y_test,
            contamination,
        )
        results.append(ae_results)
    else:
        console.print("[yellow]TensorFlow not available - skipping Autoencoder detector.[/yellow]")

    # Present results
    table = Table(title="Unsupervised Model Evaluation", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Model", style="cyan", justify="left")
    table.add_column("ROC AUC", justify="right")
    table.add_column("PR AUC", justify="right")
    table.add_column("F1", justify="right")
    table.add_column("Prec", justify="right")
    table.add_column("Rec", justify="right")
    table.add_column("Spec", justify="right")
    table.add_column("MCC", justify="right")
    table.add_column("Thr", justify="right")

    for res in results:
        table.add_row(
            res["name"],
            f"{res['roc_auc']:.3f}",
            f"{res['pr_auc']:.3f}",
            f"{res['f1']:.3f}",
            f"{res['precision']:.3f}",
            f"{res['recall']:.3f}",
            f"{res['specificity']:.3f}",
            f"{res['mcc']:.3f}",
            f"{res['threshold']:.4f}",
        )

    console.print(table)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    output_dir = os.path.dirname(args.output)
    
    with open(args.output, "w", encoding="utf-8") as fh:
        # Remove scores from JSON to keep file size reasonable
        results_for_json = []
        for res in results:
            res_copy = res.copy()
            res_copy.pop("scores", None)  # Remove scores from JSON
            results_for_json.append(res_copy)
        
        json.dump({
            "captures": pcap_files,
            "num_normals": int(len(feature_matrix)),
            "num_anomalies": int(len(anomalies)),
            "contamination": float(contamination),
            "results": results_for_json,
        }, fh, indent=2)

    console.print(f"[green]Saved evaluation report to {args.output}[/green]")
    
    # Generate visualizations
    if MATPLOTLIB_AVAILABLE:
        console.print("[cyan]Generating visualizations...[/cyan]")
        try:
            roc_path = plot_roc_curves(results, y_test, output_dir)
            console.print(f"[green]✓ ROC curves saved to {roc_path}[/green]")
            
            pr_path = plot_pr_curves(results, y_test, output_dir)
            console.print(f"[green]✓ PR curves saved to {pr_path}[/green]")
            
            cm_path = plot_confusion_matrices(results, y_test, output_dir)
            console.print(f"[green]✓ Confusion matrices saved to {cm_path}[/green]")
            
            dist_path = plot_anomaly_score_distributions(results, y_test, output_dir)
            console.print(f"[green]✓ Score distributions saved to {dist_path}[/green]")
        except Exception as e:
            console.print(f"[red]Error generating visualizations: {e}[/red]")
    else:
        console.print("[yellow]Matplotlib not available - skipping visualizations. Install with: pip install matplotlib seaborn[/yellow]")


if __name__ == "__main__":
    main()


