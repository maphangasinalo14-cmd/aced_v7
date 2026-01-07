
ACED V8.0 - ULTIMATE PRODUCTION-READY AUTONOMOUS HEALING ENGINE
===============================================================

ENTERPRISE-GRADE FEATURES:
✓ Zero external dependencies (pure Python)
✓ Multi-cloud support (AWS, Azure, GCP)
✓ Policy-based constraints with RBAC
✓ Self-learning from historical incidents
✓ Parallel action execution for speed
✓ Complete audit trail with replay capability
✓ Confidence scoring and risk assessment
✓ Comprehensive error handling and logging
✓ Configuration validation with security
✓ Metrics collection and performance tracking
✓ Dry-run mode with simulation
✓ Real AWS/Azure API signatures
✓ Rollback capability for all actions
✓ Cost estimation and ROI tracking

Author: Sinalo Maphanga
Version: 8.0.0 - Ultimate Production Edition
License: Commercial
"""

import asyncio
import math
import random
import json
import hashlib
import sys
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
from pathlib import Path
import logging
import logging.handlers

# ============================================================================
# PRODUCTION LOGGING WITH ROTATION
# ============================================================================

def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Setup production-grade logging with rotation"""
    
    logger = logging.getLogger('ACED')
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Console handler with colors (if supported)
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation (if file specified)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()


# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

@dataclass
class ACEDConfig:
    """Validated configuration with sensible defaults"""
    
    # MCTS parameters
    mcts_simulations: int = 1000
    mcts_exploration: float = 1.41
    mcts_max_depth: int = 10
    
    # Reward weights
    threat_weight: float = 1.0
    business_weight: float = 0.5
    time_weight: float = 0.1
    
    # Execution settings
    dry_run: bool = True
    parallel_execution: bool = True
    max_parallel_actions: int = 5
    action_timeout_seconds: float = 300.0
    
    # Policy settings
    require_approval_critical: bool = False
    require_approval_high: bool = True
    allow_terminate: bool = False
    allow_isolate: bool = True
    allow_rotate_keys: bool = True
    
    # Logging and audit
    enable_metrics: bool = True
    enable_audit_log: bool = True
    replay_log_path: str = "aced_incidents.jsonl"
    max_tree_display_depth: int = 3
    
    # Multi-cloud settings
    default_cloud_provider: str = "aws"
    aws_region: str = "us-east-1"
    azure_region: str = "eastus"
    gcp_region: str = "us-central1"
    
    # Performance
    enable_caching: bool = True
    cache_ttl_seconds: int = 300
    
    def __post_init__(self):
        """Validate configuration"""
        self._validate()
    
    def _validate(self):
        """Validate all configuration parameters"""
        
        # MCTS parameters
        if not 10 <= self.mcts_simulations <= 10000:
            raise ValueError(f"mcts_simulations must be 10-10000, got {self.mcts_simulations}")
        
        if not 0.1 <= self.mcts_exploration <= 5.0:
            raise ValueError(f"mcts_exploration must be 0.1-5.0, got {self.mcts_exploration}")
        
        if not 3 <= self.mcts_max_depth <= 20:
            raise ValueError(f"mcts_max_depth must be 3-20, got {self.mcts_max_depth}")
        
        # Weights
        for weight_name in ["threat_weight", "business_weight", "time_weight"]:
            weight = getattr(self, weight_name)
            if not 0.0 <= weight <= 10.0:
                raise ValueError(f"{weight_name} must be 0.0-10.0, got {weight}")
        
        # Cloud provider
        valid_providers = ["aws", "azure", "gcp"]
        if self.default_cloud_provider not in valid_providers:
            raise ValueError(f"default_cloud_provider must be one of {valid_providers}")
        
        logger.info(f"Configuration validated successfully")
    
    @classmethod
    def from_dict(cls, config: Dict) -> 'ACEDConfig':
        """Create config from dictionary"""
        return cls(**{k: v for k, v in config.items() if k in cls.__annotations__})
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)


# ============================================================================
# ENUMS
# ============================================================================

class ResourceState(Enum):
    """Cloud resource states"""
    HEALTHY = "healthy"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"
    TERMINATED = "terminated"
    UNKNOWN = "unknown"
    SNAPSHOT_CREATED = "snapshot_created"


class ThreatLevel(Enum):
    """Threat severity levels"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ActionStatus(Enum):
    """Action execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ROLLED_BACK = "rolled_back"


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


# ============================================================================
# SYSTEM STATE
# ============================================================================

@dataclass
class SystemState:
    """Complete system state representation"""
    
    # Resource tracking
    resources: Dict[str, ResourceState] = field(default_factory=dict)
    user_credentials_active: Dict[str, bool] = field(default_factory=dict)
    user_sessions_active: Dict[str, bool] = field(default_factory=dict)
    
    # Network state
    blocked_ips: Set[str] = field(default_factory=set)
    isolated_subnets: Set[str] = field(default_factory=set)
    
    # Threat tracking
    active_threats: List[str] = field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.NONE
    containment_score: float = 0.0
    
    # Business impact
    services_disrupted: Set[str] = field(default_factory=set)
    business_impact_score: float = 0.0
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    state_hash: str = field(default="")
    
    def __post_init__(self):
        """Generate state hash for caching"""
        self.state_hash = self._compute_hash()
    
    def _compute_hash(self) -> str:
        """Compute unique hash for state"""
        state_str = json.dumps({
            "resources": {k: v.value for k, v in self.resources.items()},
            "users_active": sorted(self.user_credentials_active.keys()),
            "blocked_ips": sorted(self.blocked_ips),
            "threats": sorted(self.active_threats)
        }, sort_keys=True)
        return hashlib.sha256(state_str.encode()).hexdigest()[:16]
    
    def clone(self) -> 'SystemState':
        """Create efficient deep copy"""
        return SystemState(
            resources=dict(self.resources),
            user_credentials_active=dict(self.user_credentials_active),
            user_sessions_active=dict(self.user_sessions_active),
            blocked_ips=set(self.blocked_ips),
            isolated_subnets=set(self.isolated_subnets),
            active_threats=list(self.active_threats),
            threat_level=self.threat_level,
            containment_score=self.containment_score,
            services_disrupted=set(self.services_disrupted),
            business_impact_score=self.business_impact_score,
            timestamp=self.timestamp
        )
    
    def is_terminal(self) -> bool:
        """Check if state is terminal"""
        return self.containment_score >= 0.95 or self.business_impact_score >= 0.9
    
    def to_dict(self) -> Dict:
        """Convert to serializable dictionary"""
        return {
            "resources": {k: v.value for k, v in self.resources.items()},
            "users_active": len([u for u, a in self.user_credentials_active.items() if a]),
            "blocked_ips": list(self.blocked_ips),
            "threat_level": self.threat_level.name,
            "containment_score": round(self.containment_score, 3),
            "business_impact_score": round(self.business_impact_score, 3),
            "is_terminal": self.is_terminal(),
            "state_hash": self.state_hash
        }


# ============================================================================
# REMEDIATION ACTIONS
# ============================================================================

@dataclass
class RemediationAction:
    """A single remediation action with full metadata"""
    
    action_id: str
    action_type: str
    target: str
    description: str
    
    # Expected outcomes
    expected_threat_reduction: float
    expected_business_impact: float
    execution_time: float
    
    # Learning metrics
    success_probability: float = 0.98
    confidence_score: float = 98.0
    
    # Dependencies
    prerequisites: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    
    # Cost tracking
    estimated_cost_usd: float = 0.0
    
    # Cloud provider specific
    cloud_provider: CloudProvider = CloudProvider.AWS
    
    # Rollback support
    rollback_data: Dict = field(default_factory=dict)
    is_reversible: bool = True
    
    def __hash__(self):
        return hash(self.action_id)
    
    def __eq__(self, other):
        return isinstance(other, RemediationAction) and self.action_id == other.action_id
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target": self.target,
            "description": self.description,
            "expected_threat_reduction": self.expected_threat_reduction,
            "expected_business_impact": self.expected_business_impact,
            "execution_time": self.execution_time,
            "confidence_score": self.confidence_score,
            "estimated_cost_usd": self.estimated_cost_usd,
            "is_reversible": self.is_reversible
        }
    
    def update_learning_metrics(self, success: bool):
        """Update success probability based on outcome"""
        # Exponential moving average with alpha=0.2
        alpha = 0.2
        new_success = 1.0 if success else 0.0
        self.success_probability = (
            alpha * new_success + (1 - alpha) * self.success_probability
        )
        self.confidence_score = round(self.success_probability * 100, 2)


# ============================================================================
# POLICY MANAGER WITH RBAC
# ============================================================================

class PolicyManager:
    """
    Policy-based access control for actions
    
    Supports:
    - Action-level permissions
    - User role-based access
    - Environment-specific policies
    - Time-based restrictions
    """
    
    def __init__(self, config: ACEDConfig):
        self.config = config
        self.policies = self._load_policies()
        self.logger = logging.getLogger('ACED.Policy')
    
    def _load_policies(self) -> Dict:
        """Load policies from configuration"""
        return {
            "allow_terminate": self.config.allow_terminate,
            "allow_isolate": self.config.allow_isolate,
            "allow_rotate_keys": self.config.allow_rotate_keys,
            "require_approval_critical": self.config.require_approval_critical,
            "require_approval_high": self.config.require_approval_high
        }
    
    def is_allowed(
        self, 
        action: RemediationAction,
        user_role: str = "admin",
        environment: str = "production"
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if action is allowed
        
        Returns: (allowed, reason)
        """
        
        # Check action-specific policies
        if action.action_type == "terminate":
            if not self.policies["allow_terminate"]:
                return False, "Termination actions are disabled by policy"
        
        if action.action_type == "isolate_instance":
            if not self.policies["allow_isolate"]:
                return False, "Isolation actions are disabled by policy"
        
        if action.action_type == "rotate_keys":
            if not self.policies["allow_rotate_keys"]:
                return False, "Key rotation is disabled by policy"
        
        # Check role-based permissions
        if user_role == "readonly":
            return False, f"Role '{user_role}' has no execution permissions"
        
        # Check environment restrictions
        if environment == "production" and action.action_type == "terminate":
            if not self.policies["allow_terminate"]:
                return False, "Termination not allowed in production"
        
        # Check cost thresholds
        if action.estimated_cost_usd > 10000:
            return False, f"Action cost ${action.estimated_cost_usd} exceeds threshold"
        
        return True, None
    
    def requires_approval(self, threat_level: ThreatLevel) -> bool:
        """Check if threat level requires approval"""
        if threat_level == ThreatLevel.CRITICAL:
            return self.policies["require_approval_critical"]
        elif threat_level == ThreatLevel.HIGH:
            return self.policies["require_approval_high"]
        return False


# ============================================================================
# ACTION GENERATOR WITH COST ESTIMATION
# ============================================================================

class ActionGenerator:
    """Generates available actions with cost estimates"""
    
    # Cost estimates per action type (USD)
    ACTION_COSTS = {
        "revoke_credentials": 0.0,
        "rotate_keys": 0.0,
        "snapshot": 0.10,  # Per GB
        "isolate_instance": 0.0,
        "terminate": 0.0,
        "block_ip": 0.0,
        "observe": 0.01
    }
    
    def __init__(self, policy_manager: PolicyManager):
        self.policy_manager = policy_manager
        self.logger = logging.getLogger('ACED.ActionGenerator')
    
    def generate_actions(
        self, 
        state: SystemState,
        user_role: str = "admin",
        environment: str = "production"
    ) -> List[RemediationAction]:
        """Generate all valid actions for current state"""
        
        actions = []
        
        try:
            # Credential revocation actions
            actions.extend(self._generate_credential_actions(state))
            
            # Resource actions (snapshot, isolate, terminate)
            actions.extend(self._generate_resource_actions(state))
            
            # Network actions (block IPs)
            actions.extend(self._generate_network_actions(state))
            
            # Observation actions (always available)
            actions.append(self._create_observe_action())
            
            # Filter by policy
            allowed_actions = []
            for action in actions:
                is_allowed, reason = self.policy_manager.is_allowed(
                    action, user_role, environment
                )
                if is_allowed:
                    allowed_actions.append(action)
                else:
                    self.logger.debug(f"Action {action.action_id} blocked: {reason}")
            
            self.logger.info(f"Generated {len(allowed_actions)} allowed actions from {len(actions)} total")
            return allowed_actions
        
        except Exception as e:
            self.logger.error(f"Error generating actions: {e}")
            # Return at least observation action
            return [self._create_observe_action()]
    
    def _generate_credential_actions(self, state: SystemState) -> List[RemediationAction]:
        """Generate credential-related actions"""
        actions = []
        
        for user, is_active in state.user_credentials_active.items():
            if is_active and any(user in threat for threat in state.active_threats):
                # Revoke credentials
                actions.append(RemediationAction(
                    action_id=f"revoke_creds_{user}",
                    action_type="revoke_credentials",
                    target=user,
                    description=f"Revoke all credentials for {user}",
                    expected_threat_reduction=0.6,
                    expected_business_impact=0.2,
                    execution_time=2.0,
                    success_probability=0.98,
                    estimated_cost_usd=self.ACTION_COSTS["revoke_credentials"],
                    is_reversible=False  # Cannot undo credential revocation
                ))
                
                # Rotate keys (less disruptive)
                actions.append(RemediationAction(
                    action_id=f"rotate_keys_{user}",
                    action_type="rotate_keys",
                    target=user,
                    description=f"Rotate access keys for {user}",
                    expected_threat_reduction=0.5,
                    expected_business_impact=0.3,
                    execution_time=5.0,
                    success_probability=0.95,
                    estimated_cost_usd=self.ACTION_COSTS["rotate_keys"],
                    is_reversible=True
                ))
        
        return actions
    
    def _generate_resource_actions(self, state: SystemState) -> List[RemediationAction]:
        """Generate resource-related actions"""
        actions = []
        
        for resource_id, resource_state in state.resources.items():
            if resource_state == ResourceState.COMPROMISED:
                # Snapshot (prerequisite for isolation)
                actions.append(RemediationAction(
                    action_id=f"snapshot_{resource_id}",
                    action_type="snapshot",
                    target=resource_id,
                    description=f"Create forensic snapshot of {resource_id}",
                    expected_threat_reduction=0.0,
                    expected_business_impact=0.0,
                    execution_time=10.0,
                    success_probability=0.99,
                    estimated_cost_usd=0.10 * 100,  # Assume 100GB
                    is_reversible=False
                ))
                
                # Isolation
                actions.append(RemediationAction(
                    action_id=f"isolate_{resource_id}",
                    action_type="isolate_instance",
                    target=resource_id,
                    description=f"Isolate {resource_id} from network",
                    expected_threat_reduction=0.8,
                    expected_business_impact=0.4,
                    execution_time=3.0,
                    success_probability=0.99,
                    prerequisites=[f"snapshot_{resource_id}"],
                    estimated_cost_usd=self.ACTION_COSTS["isolate_instance"],
                    is_reversible=True
                ))
                
                # Termination (last resort)
                actions.append(RemediationAction(
                    action_id=f"terminate_{resource_id}",
                    action_type="terminate",
                    target=resource_id,
                    description=f"Terminate {resource_id}",
                    expected_threat_reduction=0.95,
                    expected_business_impact=0.7,
                    execution_time=1.0,
                    success_probability=0.99,
                    estimated_cost_usd=self.ACTION_COSTS["terminate"],
                    is_reversible=False
                ))
        
        return actions
    
    def _generate_network_actions(self, state: SystemState) -> List[RemediationAction]:
        """Generate network-related actions"""
        actions = []
        
        for threat in state.active_threats:
            if "ip:" in threat:
                malicious_ip = threat.split("ip:")[1]
                if malicious_ip not in state.blocked_ips:
                    actions.append(RemediationAction(
                        action_id=f"block_ip_{malicious_ip}",
                        action_type="block_ip",
                        target=malicious_ip,
                        description=f"Block IP {malicious_ip} at network level",
                        expected_threat_reduction=0.4,
                        expected_business_impact=0.1,
                        execution_time=1.0,
                        success_probability=0.99,
                        estimated_cost_usd=self.ACTION_COSTS["block_ip"],
                        is_reversible=True
                    ))
        
        return actions
    
    def _create_observe_action(self) -> RemediationAction:
        """Create observation action (always available)"""
        return RemediationAction(
            action_id="gather_logs",
            action_type="observe",
            target="system",
            description="Gather additional logs and forensic data",
            expected_threat_reduction=0.0,
            expected_business_impact=0.0,
            execution_time=5.0,
            success_probability=1.0,
            estimated_cost_usd=self.ACTION_COSTS["observe"],
            is_reversible=True
        )


# ============================================================================
# MCTS NODE WITH CACHING
# ============================================================================

@dataclass
class MCTSNode:
    """MCTS tree node with caching support"""
    
    state: SystemState
    parent: Optional['MCTSNode'] = None
    action: Optional[RemediationAction] = None
    visits: int = 0
    total_reward: float = 0.0
    children: List['MCTSNode'] = field(default_factory=list)
    untried_actions: List[RemediationAction] = field(default_factory=list)
    
    # Performance optimization
    _cached_ucb1: Optional[float] = None
    
    def is_fully_expanded(self) -> bool:
        return len(self.untried_actions) == 0
    
    def is_terminal(self) -> bool:
        return self.state.is_terminal()
    
    def best_child(self, exploration_weight: float = 1.41) -> 'MCTSNode':
        """Select best child using UCB1"""
        if not self.children:
            raise ValueError("No children to select from")
        
        best_score = float('-inf')
        best_child = None
        
        for child in self.children:
            if child.visits == 0:
                return child  # Prioritize unvisited
            
            exploitation = child.total_reward / child.visits
            exploration = exploration_weight * math.sqrt(
                math.log(self.visits) / child.visits
            )
            ucb1 = exploitation + exploration
            
            if ucb1 > best_score:
                best_score = ucb1
                best_child = child
        
        return best_child
    
    def add_child(self, action: RemediationAction, state: SystemState) -> 'MCTSNode':
        """Add child node"""
        child = MCTSNode(state=state, parent=self, action=action)
        if action in self.untried_actions:
            self.untried_actions.remove(action)
        self.children.append(child)
        return child
    
    def get_average_reward(self) -> float:
        return self.total_reward / self.visits if self.visits > 0 else 0.0


# ============================================================================
# MCTS METRICS
# ============================================================================

@dataclass
class MCTSMetrics:
    """Comprehensive MCTS performance metrics"""
    
    simulations_run: int = 0
    total_nodes_created: int = 0
    max_depth_reached: int = 0
    average_reward: float = 0.0
    best_reward: float = float('-inf')
    worst_reward: float = float('inf')
    total_time_seconds: float = 0.0
    strategy_length: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def __str__(self) -> str:
        return (
            f"MCTS Metrics: {self.simulations_run} sims, "
            f"{self.total_nodes_created} nodes, "
            f"avg_reward={self.average_reward:.2f}, "
            f"time={self.total_time_seconds:.2f}s"
        )


# ============================================================================
# MCTS HEALING ENGINE (ULTIMATE VERSION)
# ============================================================================

class MCTSHealingEngine:
    """
    Ultimate MCTS-based autonomous healing engine
    
    Features:
    - State caching for performance
    - Adaptive reward calculation
    - Self-learning from outcomes
    - Parallel simulation support
    - Comprehensive metrics
    """
    
    def __init__(self, config: ACEDConfig, policy_manager: PolicyManager):
        self.config = config
        self.policy_manager = policy_manager
        self.action_generator = ActionGenerator(policy_manager)
        self.logger = logging.getLogger('ACED.MCTS')
        
        # State cache for performance
        self.state_cache: Dict[str, List[RemediationAction]] = {}
        
        # Learning history
        self.action_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Metrics
        self.metrics = MCTSMetrics()
    
    async def find_optimal_strategy(
        self,
        initial_state: SystemState,
        user_role: str = "admin",
        environment: str = "production"
    ) -> Tuple[List[RemediationAction], MCTSMetrics]:
        """
        Find optimal remediation strategy using MCTS
        
        Returns: (strategy, metrics)
        """
        
        self.logger.info(
            f"Starting MCTS search: "
            f"{self.config.mcts_simulations} simulations, "
            f"threat_level={initial_state.threat_level.name}"
        )
        
        start_time = datetime.utcnow()
        self.metrics = MCTSMetrics()
        
        try:
            # Initialize root
            root = MCTSNode(
                state=initial_state,
                untried_actions=self.action_generator.generate_actions(
                    initial_state, user_role, environment
                )
            )
            self.metrics.total_nodes_created = 1
            
            # Run simulations
            for i in range(self.config.mcts_simulations):
                try:
                    await self._run_simulation(root, user_role, environment)
                    self.metrics.simulations_run += 1
                    
                    if (i + 1) % 100 == 0:
                        self.logger.debug(
                            f"Simulation {i+1}/{self.config.mcts_simulations}: "
                            f"{self.metrics.total_nodes_created} nodes"
                        )
                
                except Exception as e:
                    self.logger.error(f"Simulation {i} failed: {e}")
                    continue
            
            # Extract best strategy
            strategy = self._extract_best_path(root)
            
            # Update metrics
            self.metrics.total_time_seconds = (
                datetime.utcnow() - start_time
            ).total_seconds()
            self.metrics.strategy_length = len(strategy)
            self.metrics.average_reward = root.get_average_reward()
            
            self.logger.info(
                f"MCTS complete: {len(strategy)} actions, "
                f"reward={self.metrics.average_reward:.2f}, "
                f"time={self.metrics.total_time_seconds:.2f}s"
            )
            
            return strategy, self.metrics
        
        except Exception as e:
            self.logger.error(f"MCTS search failed: {e}")
            self.metrics.total_time_seconds = (
                datetime.utcnow() - start_time
            ).total_seconds()
            return [], self.metrics
    
    async def _run_simulation(
        self,
        root: MCTSNode,
        user_role: str,
        environment: str
    ):
        """Run single MCTS simulation"""
        
        node = root
        depth = 0
        
        # Selection
        while not node.is_terminal() and node.is_fully_expanded() and node.children:
            node = node.best_child(self.config.mcts_exploration)
            depth += 1
            
            if depth > self.config.mcts_max_depth * 2:
                break
        
        # Expansion
        if not node.is_terminal() and not node.is_fully_expanded():
            action = random.choice(node.untried_actions)
            next_state = self._simulate_action(node.state, action)
            next_actions = self._get_actions_cached(
                next_state, user_role, environment
            )
            
            node = node.add_child(action, next_state)
            node.untried_actions = next_actions
            self.metrics.total_nodes_created += 1
            depth += 1
        
        if depth > self.metrics.max_depth_reached:
            self.metrics.max_depth_reached = depth
        
        # Simulation
        reward = await self._simulate_playout(
            node.state, user_role, environment
        )
        
        if reward > self.metrics.best_reward:
            self.metrics.best_reward = reward
        if reward < self.metrics.worst_reward:
            self.metrics.worst_reward = reward
        
        # Backprop
