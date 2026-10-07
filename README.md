# 🛡️ AI-Powered Terminal Process Monitor & Threat Detection

An `htop`-style Terminal User Interface (TUI) that integrates live system-call monitoring with a hybrid Machine Learning pipeline to detect malware, reverse shells, and anomalous behavior in real-time.

Developed as a cybersecurity and operating systems project at Vasavi College of Engineering by Tumma Vikranth.

---

## ✨ Features

- **Real-Time UI:** A responsive, `htop`-like terminal dashboard built with `rich` and `psutil`.
- **Live System Wiretapping:** Uses Linux `strace` to dynamically attach to high-CPU processes and intercept system calls on the fly.
- **Hybrid Machine Learning Engine:** Blends supervised and unsupervised learning for robust threat detection.
- **N-Gram Feature Extraction:** Translates raw system call sequences into contextual 3, 5, and 7-grams, utilizing the Hashing Trick to maintain performance.
- **Zero-Day Detection:** Capable of flagging unknown anomalies alongside known attack vectors (Hydra, Meterpreter, Web Shells).

---

## 🧠 Machine Learning Architecture

The threat detection engine evaluates processes using a dual-model ensemble trained on the **ADFA-LD (Australian Defence Force Academy Linux Dataset)**:

1. **The Bouncer (Logistic Regression):** A supervised model trained explicitly on the signatures of 6 known cyberattacks. It recognizes established malicious patterns instantly.
2. **The Detective (Isolation Forest):** An unsupervised anomaly detection model trained purely on normal baseline processes. If a zero-day virus attacks, this model flags the process based on structural deviations from normal behavior.

The final Threat Score is a weighted blend of both models (`70% Logistic Regression + 30% Isolation Forest`).

---

## ⚙️ Installation & Setup

**Prerequisites:**

- A Linux environment (Ubuntu/Debian recommended)
- Python 3.8+
- `strace` (Required for live system call interception)

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install strace

# 2. Clone the repository
git clone https://github.com/VikranthMaster/os.git
cd os

# 3. Set up the Python virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install required Python packages
pip install pandas scikit-learn psutil joblib rich
```

---

## 🚀 Usage

### 1. Train the ML Models

Before running the monitor, you must compile the AI "Brain" from the dataset.

```bash
python3 train.py
```

*This generates `threat_model.pkl` in your root directory.*

### 2. Run the Live Monitor

Live strace monitoring requires root privileges to attach to background processes. To ensure `sudo` uses the virtual environment's Python, run:

```bash
sudo -E env PATH=$PATH python3 monitor.py
```

### 3. Presentation & Demo Mode

If you want to showcase the AI's detection capabilities without deploying live malware, launch the monitor in demo mode. This injects mathematical simulations of ADFA-LD attacks into the UI queue:

```bash
sudo -E env PATH=$PATH python3 monitor.py --demo
```

---

## 📊 Dataset Attribution

This project utilizes the **ADFA-LD** benchmark dataset for Host-Based Intrusion Detection Systems (HIDS), developed by the UNSW Canberra Cyber research group. The models are trained on frequency metrics of 3-gram, 5-gram, and 7-gram system call sequences.
