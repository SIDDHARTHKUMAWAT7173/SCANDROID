# 🔐 SCANDROID  
### Instant OWASP Security Insights for Android APKs

SCANDROID is a lightweight static security analysis platform designed to evaluate Android APK files and instantly generate structured security insights mapped to the OWASP Mobile Top 10.

Built for national-level cybersecurity evaluation, SCANDROID focuses on clarity, speed, and executive-grade risk reporting.

---

### 🚀 Lightweight. Modular. OWASP-Aligned.

Built to deliver instant mobile security intelligence without heavyweight enterprise tooling.

---

## 👥 Team TRIMAX

- Siddharth  
- Dev  
- Aryan  

---

## 🚨 Problem Statement

Android applications frequently contain:

- Exposed exported components  
- Weak cryptographic implementations  
- Hardcoded secrets  
- Insecure WebView configurations  
- Cleartext network communication  
- Improper security configurations  

Many existing security tools are heavy, slow, and complex.

There is a need for a modular, lightweight static analysis engine that can:

- Quickly scan APK files  
- Detect real security weaknesses  
- Map findings to OWASP Mobile Top 10  
- Present executive-level risk insights  

---

## 💡 Our Solution

SCANDROID performs multi-layer static analysis of Android APKs using:

- Manifest inspection  
- DEX bytecode inspection    
- Custom rule-based vulnerability detection engine  
- Advanced weighted risk scoring  
- Interactive executive dashboard  

It transforms raw APK files into structured, understandable security intelligence.

---

## 🌍 Impact

SCANDROID enables:

- Faster security evaluation during app development
- Early detection of critical mobile vulnerabilities
- Reduced risk of insecure production releases
- Simplified security reporting for technical and non-technical stakeholders

It bridges the gap between deep security analysis and executive-level decision making.

---

## 🧠 Technical Architecture

```
User Uploads APK
        ↓
Flask Web Interface
        ↓
APK Analyzer Engine
        ↓
Androguard (APK Structure Parsing)
        ↓
Custom Static Scanners
        ↓
Risk Scoring Engine
        ↓
Executive Security Dashboard
```

---

## 🔎 Key Features

- ✔ Exported Activity / Service / Receiver / Provider detection  
- ✔ Cleartext traffic detection  
- ✔ Weak cryptography detection (MD5, SHA1, AES-ECB)  
- ✔ Hardcoded secret detection  
- ✔ WebView misconfiguration analysis  
- ✔ TLS & certificate validation checks  
- ✔ Root detection & anti-debug mechanism analysis  
- ✔ Signature verification detection  
- ✔ OWASP Mobile Top 10 vulnerability mapping  
- ✔ Advanced weighted risk scoring model  
- ✔ Executive dashboard with severity breakdown  
- ✔ JSON structured report generation  

---

## 🏆 OWASP Mobile Top 10 Coverage

| OWASP Category | Coverage |
|----------------|----------|
| M1 – Improper Credential Usage | ✅ |
| M3 – Insecure Authentication / Authorization | ✅ |
| M5 – Insecure Communication | ✅ |
| M6 – Inadequate Privacy Controls | ✅ |
| M7 – Insufficient Binary Protections | ✅ |
| M8 – Security Misconfiguration | ✅ |
| M9 – Reverse Engineering | ✅ |
| M10 – Insufficient Cryptography | ✅ |


---

## 📊 Risk Scoring Model

Each detected vulnerability is assigned a weighted score:

- Critical → 10 points  
- High → 7 points  
- Medium → 4 points  
- Low → 1 point  

The total risk score determines:

- Low Risk  
- Moderate Risk  
- High Risk  
- Critical Risk  

This enables executive-level security classification for decision-making.

---

## 🚀 Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

---

### 2️⃣ Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate     # Mac/Linux
venv\Scripts\activate        # Windows
```

---

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🖥 Run SCANDROID

```bash
python webapp.py
```

Open in browser:

```
http://127.0.0.1:5000
```

Upload an APK file to begin analysis.

---

## 📦 Requirements

- Python 3.9+
- Androguard
- Flask
- Basic system tools for APK parsing

Tested on:
- Windows
- macOS

---

## 📁 Project Structure

```
SCANDROID/
│
├── webapp.py
├── analyzer.py
│
├── scanners/
│   ├── manifest.py
│   ├── crypto.py
│   ├── secrets.py
│   ├── permissions.py
│
├── templates/
│   ├── index.html
│   ├── report.html
│
├── static/
│   ├── style.css
│
├── utils/
│   ├──owasp.py
│   ├──report.py
│   ├──severity.py
│
├──main.py
├── requirements.txt
└── README.md
```

---

## 🔬 Why Androguard?

SCANDROID uses Androguard strictly for:

- Parsing APK structure
- Extracting manifest metadata
- Extracting DEX string data

All vulnerability detection logic, OWASP mapping, and risk scoring
are implemented independently within SCANDROID.

---

## 🎯 Hackathon Context

SCANDROID was developed for a national-level hackathon under GDG club of IIT MANDI .

Our objective was to build:

- A modular static security analyzer  
- With structured OWASP mapping  
- A scalable rule-based detection engine  
- An executive security dashboard  
- A practical alternative to heavyweight tools  

---

## 🔮 Future Improvements

- Machine learning-based anomaly detection  
- Automated CI/CD pipeline integration   
- Obfuscation detection scoring  

---

## 🛡 Built by Team TRIMAX
## Thanks...

