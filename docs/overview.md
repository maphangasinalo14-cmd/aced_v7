# ACED Engine Overview

ACED uses Monte Carlo Tree Search (MCTS) to simulate remediation strategies.
Each incident is modeled as a state tree, with actions like:
- Revoke credentials
- Rotate keys
- Isolate/terminate resources
- Block IPs

The orchestrator selects the optimal path balancing containment, business impact, and time.
