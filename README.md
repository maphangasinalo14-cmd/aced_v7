# ACED V7.0 - Autonomous Healing Engine (Unified Multi-Cloud Edition)

Autonomous incident response engine that detects, simulates, and acts on security threats in real-time using Monte Carlo Tree Search (MCTS).

Built to adapt, learn, and remediate incidents across AWS and Azure environments with configurable policies, parallel execution, and dry-run support.

---

## 📸 Simulation Output

Here’s a snapshot of ACED V7.0 running a high-severity incident simulation:

![ACED V7.0 Output](screenshots/aced_v7_output.png)

*Strategy: rotate keys, revoke credentials, isolate compromised resources. Confidence: 100%. Containment: False.*

---

## ✨ Features

- 🧠 Monte Carlo Tree Search (MCTS) for optimal remediation strategies  
- 🔐 Actions: revoke credentials, rotate keys, isolate/snapshot/terminate resources, block IPs, observe  
- ☁️ Multi-cloud execution (AWS + Azure) with dry-run mode for safe testing  
- ⚖️ Adaptive reward function based on severity, business impact, and time  
- ⚡ Parallel execution of independent actions  
- 🛡️ Policy constraints to enforce safe automation  
- 📊 Confidence scoring for each action based on historical success  
- 📝 Incident replay logging with timezone-aware timestamps  

---

## 📂 Project Structure

- `aced_v7.py` → Main engine implementation  
- `screenshots/` → Example output from live simulation  
- Executors:
  - `AWSExecutor` → Simulates AWS-specific actions  
  - `AzureExecutor` → Simulates Azure-specific actions  

---

## 🚀 Usage

Run the engine with Python 3.12+:

```bash
python3 aced_v7.py
