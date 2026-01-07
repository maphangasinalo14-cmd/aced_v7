"""
ACED V7.0 - Live Autonomous Healing Engine (Unified)
====================================================

Autonomous incident response that detects, simulates, and acts on security threats in real-time.

Features:
- Monte Carlo Tree Search for optimal remediation
- Expanded actions: revoke credentials, rotate keys, isolate/snapshot/terminate resources, block IPs, observe
- Multi-cloud execution (AWS + Azure) with dry-run mode for safe testing
- Full audit logging and metrics tracking
- Self-learning from every incident (adaptive success probabilities)
- Policy constraints, parallel execution, confidence scoring, incident replay logging

Author: Sinalo Maphanga
Version: 7.0.0 - Unified Multi-Cloud Edition
"""

import asyncio
import math
import random
import json
from datetime import datetime, UTC
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import logging

try:
    import numpy as np
except ImportError:
    np = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aced")

# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================

class ResourceState(Enum):
    HEALTHY = "healthy"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"
    TERMINATED = "terminated"
    UNKNOWN = "unknown"

class ThreatLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class SystemState:
    resources: Dict[str, ResourceState] = field(default_factory=dict)
    user_credentials_active: Dict[str, bool] = field(default_factory=dict)
    user_sessions_active: Dict[str, bool] = field(default_factory=dict)
    blocked_ips: Set[str] = field(default_factory=set)
    isolated_subnets: Set[str] = field(default_factory=set)
    active_threats: List[str] = field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.NONE
    containment_score: float = 0.0
    services_disrupted: Set[str] = field(default_factory=set)
    business_impact_score: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def clone(self) -> 'SystemState':
        return SystemState(
            resources=self.resources.copy(),
            user_credentials_active=self.user_credentials_active.copy(),
            user_sessions_active=self.user_sessions_active.copy(),
            blocked_ips=self.blocked_ips.copy(),
            isolated_subnets=self.isolated_subnets.copy(),
            active_threats=self.active_threats.copy(),
            threat_level=self.threat_level,
            containment_score=self.containment_score,
            services_disrupted=self.services_disrupted.copy(),
            business_impact_score=self.business_impact_score,
            timestamp=datetime.now(UTC)
        )

    def is_terminal(self) -> bool:
        return self.containment_score >= 0.95 or self.business_impact_score >= 0.9

@dataclass
class RemediationAction:
    action_id: str
    action_type: str
    target: str
    description: str
    expected_threat_reduction: float
    expected_business_impact: float
    execution_time: float
    success_probability: float
    prerequisites: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    confidence_score: float = 100.0

    def __hash__(self):
        return hash(self.action_id)

    def __eq__(self, other):
        return isinstance(other, RemediationAction) and self.action_id == other.action_id

# ============================================================================
# POLICY MANAGER
# ============================================================================

class PolicyManager:
    def __init__(self, policies: Dict[str, bool]):
        self.policies = policies

    def is_allowed(self, action: RemediationAction) -> bool:
        # Example policies:
        # - allow_terminate: whether termination actions are permitted
        # - allow_isolate: whether isolation actions are permitted
        # - allow_rotate_keys: whether key rotation is permitted
        # Defaults to True if not specified
        if action.action_type == "terminate" and not self.policies.get("allow_terminate", True):
            return False
        if action.action_type == "isolate_instance" and not self.policies.get("allow_isolate", True):
            return False
        if action.action_type == "rotate_keys" and not self.policies.get("allow_rotate_keys", True):
            return False
        return True

# ============================================================================
# ACTION GENERATOR
# ============================================================================

class ActionGenerator:
    def __init__(self, policy_manager: PolicyManager):
        self.logger = logger
        self.policy_manager = policy_manager

    def generate_actions(self, state: SystemState) -> List[RemediationAction]:
        actions: List[RemediationAction] = []

        # Credential actions
        for user, is_active in state.user_credentials_active.items():
            if is_active and user in [t.split(":")[-1] for t in state.active_threats if t.startswith("user:")]:
                actions.append(RemediationAction(
                    action_id=f"revoke_creds_{user}",
                    action_type="revoke_credentials",
                    target=user,
                    description=f"Revoke credentials for {user}",
                    expected_threat_reduction=0.6,
                    expected_business_impact=0.2,
                    execution_time=2.0,
                    success_probability=0.98
                ))
                actions.append(RemediationAction(
                    action_id=f"rotate_keys_{user}",
                    action_type="rotate_keys",
                    target=user,
                    description=f"Rotate access keys for {user}",
                    expected_threat_reduction=0.5,
                    expected_business_impact=0.3,
                    execution_time=5.0,
                    success_probability=0.95
                ))

        # Instance isolation/termination/snapshot
        for resource_id, resource_state in state.resources.items():
            if resource_state == ResourceState.COMPROMISED:
                actions.append(RemediationAction(
                    action_id=f"snapshot_{resource_id}",
                    action_type="snapshot",
                    target=resource_id,
                    description=f"Create forensic snapshot of {resource_id}",
                    expected_threat_reduction=0.0,
                    expected_business_impact=0.0,
                    execution_time=10.0,
                    success_probability=0.99
                ))
                actions.append(RemediationAction(
                    action_id=f"isolate_{resource_id}",
                    action_type="isolate_instance",
                    target=resource_id,
                    description=f"Isolate instance {resource_id}",
                    expected_threat_reduction=0.8,
                    expected_business_impact=0.4,
                    execution_time=3.0,
                    success_probability=0.99,
                    prerequisites=[f"snapshot_{resource_id}"]
                ))
                actions.append(RemediationAction(
                    action_id=f"terminate_{resource_id}",
                    action_type="terminate",
                    target=resource_id,
                    description=f"Terminate instance {resource_id}",
                    expected_threat_reduction=0.95,
                    expected_business_impact=0.7,
                    execution_time=1.0,
                    success_probability=0.99
                ))

        # Network actions
        for threat in state.active_threats:
            if "ip:" in threat:
                malicious_ip = threat.split("ip:")[1]
                if malicious_ip not in state.blocked_ips:
                    actions.append(RemediationAction(
                        action_id=f"block_ip_{malicious_ip}",
                        action_type="block_ip",
                        target=malicious_ip,
                        description=f"Block IP {malicious_ip}",
                        expected_threat_reduction=0.4,
                        expected_business_impact=0.1,
                        execution_time=1.0,
                        success_probability=0.99
                    ))

        # Observation actions
        actions.append(RemediationAction(
            action_id="gather_logs",
            action_type="observe",
            target="system",
            description="Gather additional logs for analysis",
            expected_threat_reduction=0.0,
            expected_business_impact=0.0,
            execution_time=5.0,
            success_probability=1.0
        ))

        # Apply policy constraints
        return [a for a in actions if self.policy_manager.is_allowed(a)]

# ============================================================================
# MCTS NODE
# ============================================================================

@dataclass
class MCTSNode:
    state: SystemState
    parent: Optional['MCTSNode'] = None
    action: Optional[RemediationAction] = None
    visits: int = 0
    total_reward: float = 0.0
    children: List['MCTSNode'] = field(default_factory=list)
    untried_actions: List[RemediationAction] = field(default_factory=list)

    def is_fully_expanded(self) -> bool:
        return len(self.untried_actions) == 0

    def is_terminal(self) -> bool:
        return self.state.is_terminal()

    def best_child(self, exploration_weight: float = 1.41) -> 'MCTSNode':
        scores: List[float] = []
        for child in self.children:
            if child.visits == 0:
                ucb1 = float('inf')
            else:
                exploitation = child.total_reward / child.visits
                exploration = exploration_weight * math.sqrt(max(1e-9, math.log(self.visits)) / child.visits)
                ucb1 = exploitation + exploration
            scores.append(ucb1)
        if np is not None:
            return self.children[int(np.argmax(scores))]
        return self.children[scores.index(max(scores))]

    def add_child(self, action: RemediationAction, state: SystemState) -> 'MCTSNode':
        child = MCTSNode(state=state, parent=self, action=action)
        if action in self.untried_actions:
            self.untried_actions.remove(action)
        self.children.append(child)
        return child

# ============================================================================
# MCTS HEALING ENGINE
# ============================================================================

class MCTSHealingEngine:
    def __init__(self, config: Dict, policy_manager: PolicyManager):
        self.config = config
        self.action_generator = ActionGenerator(policy_manager)
        self.logger = logger
        self.num_simulations = config.get("mcts_simulations", 1000)
        self.exploration_weight = config.get("mcts_exploration", 1.41)
        self.max_depth = config.get("mcts_max_depth", 10)
        self.threat_weight = config.get("threat_weight", 1.0)
        self.business_weight = config.get("business_weight", 0.5)
        self.time_weight = config.get("time_weight", 0.1)
        self.dry_run = config.get("dry_run", True)
        self.action_history: Dict[str, List[float]] = defaultdict(list)

    async def find_optimal_strategy(self, initial_state: SystemState) -> List[RemediationAction]:
        root = MCTSNode(
            state=initial_state,
            untried_actions=self.action_generator.generate_actions(initial_state)
        )
        for _ in range(self.num_simulations):
            node = root

            # Selection
            while not node.is_terminal() and node.is_fully_expanded() and node.children:
                node = node.best_child(self.exploration_weight)

            # Expansion
            if not node.is_terminal() and not node.is_fully_expanded():
                action = random.choice(node.untried_actions)
                next_state = self._simulate_action(node.state, action)
                next_actions = self.action_generator.generate_actions(next_state)
                node = node.add_child(action, next_state)
                node.untried_actions = next_actions

            # Simulation
            reward = await self._simulate_playout(node.state)

            # Backpropagation
            while node is not None:
                node.visits += 1
                node.total_reward += reward
                node = node.parent

        return self._extract_best_path(root)

    def _simulate_action(self, state: SystemState, action: RemediationAction) -> SystemState:
        next_state = state.clone()

        if action.action_type == "revoke_credentials":
            next_state.user_credentials_active[action.target] = False
            next_state.containment_score += action.expected_threat_reduction * 0.3
            next_state.business_impact_score += action.expected_business_impact * 0.2

        elif action.action_type == "rotate_keys":
            next_state.containment_score += action.expected_threat_reduction * 0.25
            next_state.business_impact_score += action.expected_business_impact * 0.15

        elif action.action_type == "isolate_instance":
            next_state.resources[action.target] = ResourceState.QUARANTINED
            next_state.containment_score += action.expected_threat_reduction * 0.4
            next_state.business_impact_score += action.expected_business_impact * 0.3
            next_state.services_disrupted.add(action.target)

        elif action.action_type == "terminate":
            next_state.resources[action.target] = ResourceState.TERMINATED
            next_state.containment_score += action.expected_threat_reduction * 0.5
            next_state.business_impact_score += action.expected_business_impact * 0.5
            next_state.services_disrupted.add(action.target)

        elif action.action_type == "snapshot":
            # No direct containment impact, but prerequisite for isolation
            pass

        elif action.action_type == "block_ip":
            next_state.blocked_ips.add(action.target)
            next_state.containment_score += action.expected_threat_reduction * 0.2
            next_state.business_impact_score += action.expected_business_impact * 0.05

        elif action.action_type == "observe":
            # No direct impact; improves visibility
            pass

        # Clamp scores
        next_state.containment_score = min(1.0, max(0.0, next_state.containment_score))
        next_state.business_impact_score = min(1.0, max(0.0, next_state.business_impact_score))
        return next_state

    async def _simulate_playout(self, state: SystemState) -> float:
        current_state = state.clone()
        depth = 0
        total_time = 0.0

        while not current_state.is_terminal() and depth < self.max_depth:
            actions = self.action_generator.generate_actions(current_state)
            if not actions:
                break
            action = self._weighted_random_action(actions)
            current_state = self._simulate_action(current_state, action)
            total_time += action.execution_time
            depth += 1

        return self._calculate_reward(current_state, total_time)

    def _weighted_random_action(self, actions: List[RemediationAction]) -> RemediationAction:
        weights: List[float] = []
        for action in actions:
            base = (action.expected_threat_reduction * self.threat_weight
                    - action.expected_business_impact * self.business_weight + 0.1)
            learned = getattr(action, "success_probability", 0.9)
            weight = max(0.01, base * (0.5 + 0.5 * learned))
            weights.append(weight)

        total = sum(weights)
        probs = [w / total for w in weights] if total > 0 else [1.0 / len(actions)] * len(actions)
        return random.choices(actions, weights=probs, k=1)[0]

    def _calculate_reward(self, state: SystemState, total_time: float) -> float:
        # Adaptive weights based on severity
        severity = state.threat_level
        if severity == ThreatLevel.CRITICAL:
            threat_w = self.threat_weight * 1.5
            business_w = self.business_weight * 0.5
        elif severity == ThreatLevel.LOW:
            threat_w = self.threat_weight * 0.5
            business_w = self.business_weight * 1.5
        else:
            threat_w = self.threat_weight
            business_w = self.business_weight

        containment_reward = state.containment_score * threat_w
        business_penalty = state.business_impact_score * business_w
        time_penalty = (total_time / 60.0) * self.time_weight
        reward = containment_reward - business_penalty - time_penalty

        if state.containment_score >= 0.95 and state.business_impact_score < 0.3:
            reward += 2.0
        return reward

    def _extract_best_path(self, root: MCTSNode) -> List[RemediationAction]:
        path: List[RemediationAction] = []
        node = root
        while node.children:
            best_child = max(node.children, key=lambda c: (c.total_reward / c.visits) if c.visits > 0 else -float('inf'))
            if best_child.action:
                path.append(best_child.action)
            node = best_child
            if node.state.containment_score >= 0.95:
                break
        return path

    async def execute_strategy(self, strategy: List[RemediationAction], executor) -> List[Dict]:
        # Parallel execution to reduce total remediation time
        tasks = []
        for action in strategy:
            if self.dry_run:
                tasks.append(asyncio.create_task(self._simulate_execution(action)))
            else:
                tasks.append(asyncio.create_task(executor.execute_action(action)))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        final_results = []
        for action, res in zip(strategy, results):
            if isinstance(res, Exception):
                final_results.append({"action": action.action_id, "status": "failed", "error": str(res)})
            else:
                final_results.append(res)
            self._update_action_statistics(action, final_results[-1])
        return final_results

    async def _simulate_execution(self, action: RemediationAction) -> Dict:
        await asyncio.sleep(action.execution_time / 10)  # scaled down for simulation
        return {"action": action.action_id, "status": "success", "details": {"simulated": True}}

    def _update_action_statistics(self, action: RemediationAction, result: Dict):
        success = 1.0 if result.get("status") == "success" else 0.0
        self.action_history[action.action_type].append(success)
        history = self.action_history[action.action_type]
        action.success_probability = sum(history) / len(history)
        action.confidence_score = round(action.success_probability * 100, 2)

# ============================================================================
# AUTONOMOUS HEALING ORCHESTRATOR (MULTI-CLOUD)
# ============================================================================

class AutonomousHealingOrchestrator:
    def __init__(self, config: Dict, aws_executor, azure_executor, policy_manager: PolicyManager):
        self.mcts_engine = MCTSHealingEngine(config, policy_manager)
        self.aws_executor = aws_executor
        self.azure_executor = azure_executor
        self.logger = logger
        self.incident_history: List[Dict] = []
        self.replay_log_path = config.get("replay_log_path", "incident_log.json")

    async def handle_incident(self, threat_detection: Dict, platform: str = "aws") -> Dict:
        incident_id = threat_detection["detection_id"]
        current_state = await self._build_system_state(threat_detection)

        optimal_strategy = await self.mcts_engine.find_optimal_strategy(current_state)

        executor = self.aws_executor if platform.lower() == "aws" else self.azure_executor
        execution_results = await self.mcts_engine.execute_strategy(optimal_strategy, executor)

        # Recompute final state (simulate effects of chosen actions)
        final_state = current_state.clone()
        for action in optimal_strategy:
            final_state = self.mcts_engine._simulate_action(final_state, action)

        contained = final_state.containment_score >= 0.95
        outcome = {
            "incident_id": incident_id,
            "platform": platform,
            "strategy": [
                {
                    "id": a.action_id,
                    "type": a.action_type,
                    "target": a.target,
                    "confidence": a.confidence_score
                } for a in optimal_strategy
            ],
            "execution_results": execution_results,
            "contained": contained,
            "total_time": sum(a.execution_time for a in optimal_strategy),
            "business_impact": final_state.business_impact_score,
            "timestamp": datetime.now(UTC).isoformat()
        }
        self.incident_history.append(outcome)
        self._append_replay_log(outcome)
        return outcome

    def _append_replay_log(self, outcome: Dict):
        try:
            with open(self.replay_log_path, "a") as f:
                f.write(json.dumps(outcome) + "\n")
        except Exception as e:
            self.logger.warning(f"Failed to write replay log: {e}")

    async def _build_system_state(self, threat_detection: Dict) -> SystemState:
        state = SystemState()
        severity_map = {
            "critical": ThreatLevel.CRITICAL,
            "high": ThreatLevel.HIGH,
            "medium": ThreatLevel.MEDIUM,
            "low": ThreatLevel.LOW
        }
        state.threat_level = severity_map.get(threat_detection.get("severity", "medium"), ThreatLevel.MEDIUM)

        # Resources
        for resource in threat_detection.get("affected_resources", []):
            state.resources[resource] = ResourceState.COMPROMISED
            state.active_threats.append(f"resource:{resource}")

        # Users
        for user in threat_detection.get("affected_users", []):
            user_name = user.split("/")[-1] if "/" in user else user
            state.user_credentials_active[user_name] = True
            state.user_sessions_active[user_name] = True
            state.active_threats.append(f"user:{user_name}")

        # Network indicators
        for ip in threat_detection.get("malicious_ips", []):
            state.active_threats.append(f"ip:{ip}")

        return state

# ============================================================================
# EXECUTOR INTERFACES (PLACEHOLDERS)
# ============================================================================

class BaseExecutor:
    async def execute_action(self, action: RemediationAction) -> Dict:
        raise NotImplementedError

class AWSExecutor(BaseExecutor):
    async def execute_action(self, action: RemediationAction) -> Dict:
        await asyncio.sleep(0.05)  # Simulate latency
        return {"action": action.action_id, "status": "success", "details": {"provider": "aws"}}

class AzureExecutor(BaseExecutor):
    async def execute_action(self, action: RemediationAction) -> Dict:
        await asyncio.sleep(0.05)  # Simulate latency
        return {"action": action.action_id, "status": "success", "details": {"provider": "azure"}}

# ============================================================================
# USAGE EXAMPLE (ASYNC)
# ============================================================================

async def main():
    print("Starting ACED V7.0 simulation...")
    config = {
        "mcts_simulations": 800,
        "mcts_exploration": 1.41,
        "mcts_max_depth": 10,
        "threat_weight": 1.0,
        "business_weight": 0.5,
        "time_weight": 0.1,
        "dry_run": True,
        "replay_log_path": "incident_log.json"
    }

    # Example policies: disallow termination in this environment
    policy_manager = PolicyManager({
        "allow_terminate": False,
        "allow_isolate": True,
        "allow_rotate_keys": True
    })

    aws_exec = AWSExecutor()
    azure_exec = AzureExecutor()
    orchestrator = AutonomousHealingOrchestrator(config, aws_exec, azure_exec, policy_manager)

    threat_detection = {
        "detection_id": "INC-2026-002",
        "severity": "high",
        "affected_resources": ["db01", "web02"],
        "affected_users": ["arn:aws:iam::123456789012:user/alice", "bob"],
        "malicious_ips": ["203.0.113.42"]
    }

    outcome = await orchestrator.handle_incident(threat_detection, platform="aws")
    logger.info(f"Outcome: {outcome}")

if __name__ == "__main__":
    asyncio.run(main())
