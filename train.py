#!/usr/bin/env python3
"""
Train the process-threat model from the ADFA-LD n-gram files:

    TRAINING/<CLASS>/top30%_3tupple.txt  (also 5 / 7)   lines like  (('168','168','168'), 2295)

Run from ~/osdataset:   python train.py
Output: adfa_model.pkl  (LogReg multi-class classifier + Isolation Forest + demo traces)
"""
import argparse
import ast
import os
import re
import sys

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction import FeatureHasher
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import Normalizer

from threatcore import (HASH_DIM, NS, WINDOW, build_normal_stats, counts_to_dict,
                        iso_features, make_trace)


def parse_ngram_file(path):
    out = {}
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                gram, cnt = ast.literal_eval(line)
                out[tuple(int(x) for x in gram)] = int(cnt)
            except Exception:
                continue  # skip malformed line
    return out


def load_profiles(root):
    """root/<CLASS>/*{3,5,7}tupple*.txt -> {CLASS: {n: {gram: count}}}"""
    prof = {}
    for cls in sorted(os.listdir(root)):
        d = os.path.join(root, cls)
        if not os.path.isdir(d):
            continue
        per_n = {}
        for fn in os.listdir(d):
            m = re.search(r"(\d+)\s*-?tup", fn.lower())
            if m and fn.lower().endswith(".txt") and int(m.group(1)) in NS:
                per_n[int(m.group(1))] = parse_ngram_file(os.path.join(d, fn))
        if all(per_n.get(n) for n in NS):
            prof[cls.upper()] = per_n
            print(f"  loaded {cls:10s} " + "  ".join(f"{n}-gram: {len(per_n[n]):>6}" for n in NS))
        else:
            print(f"  [skip] {cls}: missing/empty n-gram files for {NS}")
    return prof


def sample_windows(profile, label, count, rng, k=WINDOW - 6):
    """Draw `count` pseudo-windows (k n-grams per n) from a class's n-gram distribution."""
    samplers = {}
    for n in NS:
        grams = list(profile[n])
        w = np.fromiter((profile[n][g] for g in grams), dtype=float, count=len(grams))
        samplers[n] = (grams, np.cumsum(w / w.sum()))
    out = []
    for _ in range(count):
        counts = {}
        for n in NS:
            grams, cdf = samplers[n]
            idx = np.minimum(np.searchsorted(cdf, rng.random(k)), len(grams) - 1)
            u, c = np.unique(idx, return_counts=True)
            counts[n] = {grams[i]: int(v) for i, v in zip(u, c)}
        out.append((counts, label))
    return out


def evaluate(title, wins, pipe, iso, stats, classes, thr=0.5):
    y = np.array([lab for _, lab in wins])
    proba = pipe.predict_proba([counts_to_dict(c) for c, _ in wins])
    pred = np.array(classes)[proba.argmax(1)]
    p_att = 1.0 - proba[:, classes.index("NORMAL")]
    df = iso.decision_function(np.array([iso_features(c, stats) for c, _ in wins]))
    iso_p = 1.0 / (1.0 + np.exp(np.clip(10.0 * df, -50, 50)))
    threat = 0.7 * p_att + 0.3 * iso_p
    is_att = y != "NORMAL"
    present = [c for c in classes if c in set(y)]

    print(f"\n===== {title}  ({len(wins)} windows) =====")
    print(f"multi-class accuracy: {(pred == y).mean():.3f}")
    print(classification_report(y, pred, labels=present, zero_division=0))
    print("confusion matrix (rows=true, cols=pred):", present)
    print(confusion_matrix(y, pred, labels=present))
    print("\nbinary detection (attack vs normal):")
    for name, flag in (("LogReg only       (p_attack>=0.5)", p_att >= 0.5),
                       ("IsolationForest   (score<0)      ", df < 0),
                       (f"COMBINED          (threat>={thr})  ", threat >= thr)):
        det = f"{flag[is_att].mean():.3f}" if is_att.any() else "n/a"
        fa = f"{flag[~is_att].mean():.3f}" if (~is_att).any() else "n/a"
        print(f"  {name}: attack detection rate={det}   false-alarm rate={fa}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="TRAINING")
    ap.add_argument("--validate", default="VALIDATE")
    ap.add_argument("--out", default="adfa_model.pkl")
    ap.add_argument("--windows", type=int, default=1000, help="pseudo-windows per class")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)

    print(f"Loading {a.train} ...")
    train = load_profiles(a.train)
    if "NORMAL" not in train or len(train) < 2:
        sys.exit("Need a NORMAL folder and at least one ATTACK-* folder with 3/5/7 tuple files.")

    wins = []
    for cls in train:
        wins += sample_windows(train[cls], cls, a.windows, rng)
    print(f"\nGenerated {len(wins)} training windows ({a.windows}/class, {WINDOW - 6} n-grams per n each)")

    print("Training LogisticRegression ...")
    pipe = Pipeline([
        ("hash", FeatureHasher(n_features=HASH_DIM, input_type="dict", alternate_sign=False)),
        ("norm", Normalizer(norm="l2")),
        ("lr", LogisticRegression(C=20.0, max_iter=500, class_weight="balanced")),
    ])
    pipe.fit([counts_to_dict(c) for c, _ in wins], [lab for _, lab in wins])
    classes = [str(c) for c in pipe.named_steps["lr"].classes_]

    print("Training Isolation Forest on NORMAL windows only ...")
    stats = build_normal_stats(train["NORMAL"])
    Xn = np.array([iso_features(c, stats) for c, lab in wins if lab == "NORMAL"])
    iso = IsolationForest(n_estimators=300, contamination=0.01, random_state=a.seed).fit(Xn)

    held_out = None
    if os.path.isdir(a.validate):
        print(f"\nLoading {a.validate} ...")
        try:
            val = {k: v for k, v in load_profiles(a.validate).items() if k in classes}
            if val:
                held_out = [w for cls in val for w in sample_windows(val[cls], cls, 300, rng)]
        except Exception as e:  # unexpected layout
            print(f"  could not use {a.validate}: {e}")
    if held_out:
        evaluate("VALIDATION (independent profiles)", held_out, pipe, iso, stats, classes)
    else:
        print("\n[!] No usable VALIDATE data -> evaluating on fresh windows from the TRAINING profiles (optimistic).")
        fresh = [w for cls in train for w in sample_windows(train[cls], cls, 300, rng)]
        evaluate("FRESH WINDOWS FROM TRAINING PROFILES", fresh, pipe, iso, stats, classes)

    demo = {cls: [make_trace(train[cls][7], 600, rng)] for cls in train}
    joblib.dump({"pipe": pipe, "iso": iso, "stats": stats, "classes": classes, "demo": demo}, a.out)
    print(f"\nSaved model -> {a.out}  ({os.path.getsize(a.out) / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
