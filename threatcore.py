"""Shared logic for the AI process monitor (used by train.py and monitor.py)."""
import math
from collections import Counter

import numpy as np

NS = (3, 5, 7)            # n-gram sizes present in the ADFA-LD tuple files
WINDOW = 200              # syscalls per scoring window
HASH_DIM = 2 ** 16        # hashed feature space for the classifier
MIN_CALLS = 60            # fewer syscalls than this in a scan -> "idle", no verdict
_TAIL = 1_000_000         # smoothing mass for n-grams never seen in NORMAL


def seq_to_counts(seq):
    """syscall list -> {n: Counter(ngram_tuple -> count)}"""
    return {n: Counter(tuple(seq[i:i + n]) for i in range(len(seq) - n + 1)) for n in NS}


def counts_to_dict(counts):
    """flatten {n: {gram: count}} into one string-keyed dict for FeatureHasher"""
    d = {}
    for n, c in counts.items():
        for g, v in c.items():
            d[f"{n}:" + "-".join(map(str, g))] = v
    return d


def build_normal_stats(normal_profile):
    """log-probabilities of every n-gram under the NORMAL profile (+ unseen value)"""
    stats = {}
    for n in NS:
        prof = normal_profile[n]
        denom = float(sum(prof.values())) + 0.5 * _TAIL
        lp = {g: math.log((c + 0.5) / denom) for g, c in prof.items()}
        stats[n] = (lp, math.log(0.5 / denom))
    return stats


def iso_features(counts, stats):
    """6 compact features for Isolation Forest: per n -> (novelty rate, mean log-prob under NORMAL)"""
    feats = []
    for n in NS:
        lp, unseen = stats[n]
        c = counts[n]
        tot = sum(c.values())
        if tot == 0:
            feats += [1.0, unseen]
            continue
        novel = sum(v for g, v in c.items() if g not in lp) / tot
        mean_lp = sum(v * lp.get(g, unseen) for g, v in c.items()) / tot
        feats += [novel, mean_lp]
    return feats


def make_trace(prof7, length, rng):
    """Build a syscall sequence by chaining 7-grams (used for --demo simulation)."""
    grams = list(prof7)
    w = np.array([prof7[g] for g in grams], dtype=float)
    cdf = np.cumsum(w / w.sum())
    nxt = {}
    for g, c in prof7.items():
        toks, ws = nxt.setdefault(g[:6], ([], []))
        toks.append(g[6])
        ws.append(c)

    def fresh():
        return list(grams[min(int(np.searchsorted(cdf, rng.random())), len(grams) - 1)])

    seq = fresh()
    while len(seq) < length:
        opts = nxt.get(tuple(seq[-6:]))
        if opts is None:
            seq += fresh()
        else:
            toks, ws = opts
            p = np.array(ws, dtype=float)
            seq.append(toks[int(rng.choice(len(toks), p=p / p.sum()))])
    return [int(x) for x in seq[:length]]


class Detector:
    """Loads the trained model and scores a window of ADFA-LD style syscall numbers."""

    def __init__(self, path):
        import joblib
        m = joblib.load(path)
        self.pipe, self.iso, self.stats = m["pipe"], m["iso"], m["stats"]
        self.classes = list(m["classes"])
        self.demo = m.get("demo", {})
        self.i_norm = self.classes.index("NORMAL")

    def score(self, seq):
        seq = [int(x) for x in seq][-WINDOW:]
        if len(seq) < MIN_CALLS:
            return None
        counts = seq_to_counts(seq)
        proba = self.pipe.predict_proba([counts_to_dict(counts)])[0]
        p_attack = float(1.0 - proba[self.i_norm])
        masked = proba.copy()
        masked[self.i_norm] = -1.0
        label = self.classes[int(masked.argmax())]
        df = float(self.iso.decision_function([iso_features(counts, self.stats)])[0])
        iso_p = 1.0 / (1.0 + math.exp(max(-50.0, min(50.0, 10.0 * df))))
        threat = 0.7 * p_attack + 0.3 * iso_p
        return {"threat": threat, "p_attack": p_attack, "iso": iso_p,
                "label": label, "calls": len(seq)}
