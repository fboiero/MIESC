"""
MIESC Agent Orchestrator
=========================

Coordinates execution of multiple security agents.
Handles selection, parallel execution, and result consolidation.
"""

import logging
import concurrent.futures
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path
import time

from src.core.agent_protocol import (
    SecurityAgent,
    AnalysisResult,
    AnalysisStatus,
    AgentCapability,
    AgentSpeed
)
from src.core.agent_registry import AgentRegistry

logger = logging.getLogger(__name__)


class SelectionCriteria:
    """Criteria for agent selection"""

    def __init__(self,
                 language: Optional[str] = None,
                 capabilities: Optional[List[AgentCapability]] = None,
                 free_only: bool = False,
                 max_cost: Optional[float] = None,
                 max_speed: Optional[AgentSpeed] = None,
                 specific_agents: Optional[List[str]] = None,
                 exclude_agents: Optional[List[str]] = None):
        """
        Args:
            language: Required language support
            capabilities: Required capabilities
            free_only: Only select free agents
            max_cost: Maximum cost per agent
            max_speed: Maximum acceptable speed
            specific_agents: Only use these agents (if available)
            exclude_agents: Never use these agents
        """
        self.language = language
        self.capabilities = capabilities or []
        self.free_only = free_only
        self.max_cost = max_cost
        self.max_speed = max_speed
        self.specific_agents = specific_agents
        self.exclude_agents = exclude_agents or []


class OrchestrationResult:
    """Results from orchestrated analysis"""

    def __init__(self):
        self.results: Dict[str, AnalysisResult] = {}
        self.total_execution_time: float = 0
        self.total_cost: float = 0
        self.agents_run: int = 0
        self.agents_success: int = 0
        self.agents_failed: int = 0
        self.consolidated_findings: List[Dict] = []
        self.timestamp: datetime = datetime.now()

    def add_result(self, agent_name: str, result: AnalysisResult, agent_cost: float):
        """Add an agent's result"""
        self.results[agent_name] = result
        self.agents_run += 1

        if result.status == AnalysisStatus.SUCCESS:
            self.agents_success += 1
        else:
            self.agents_failed += 1

        self.total_execution_time += result.execution_time
        self.total_cost += agent_cost

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        all_findings = []
        for result in self.results.values():
            if result.status == AnalysisStatus.SUCCESS:
                all_findings.extend(result.findings)

        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for finding in all_findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'total_findings': len(all_findings),
            'severity_counts': severity_counts,
            'agents_run': self.agents_run,
            'agents_success': self.agents_success,
            'agents_failed': self.agents_failed,
            'total_cost': self.total_cost,
            'total_time': self.total_execution_time,
            'timestamp': self.timestamp.isoformat()
        }


class AgentOrchestrator:
    """
    Orchestrates security analysis across multiple agents.

    Features:
    - Automatic agent discovery
    - Intelligent agent selection
    - Parallel execution
    - Result consolidation
    - Error handling
    """

    def __init__(self, registry: Optional[AgentRegistry] = None):
        """
        Args:
            registry: AgentRegistry instance (creates new if None)
        """
        self.registry = registry or AgentRegistry()
        self._initialized = False

    def initialize(self):
        """Initialize orchestrator by discovering agents"""
        if not self._initialized:
            logger.info("Initializing orchestrator...")
            self.registry.discover_all()
            self._initialized = True
            logger.info(f"Orchestrator initialized with {len(self.registry)} agents")

    def select_agents(self,
                     contract: str,
                     criteria: SelectionCriteria) -> List[SecurityAgent]:
        """
        Select appropriate agents based on criteria.

        Args:
            contract: Path to contract file
            criteria: Selection criteria

        Returns:
            List of selected agents
        """
        if not self._initialized:
            self.initialize()

        # Start with all available agents
        candidates = [a for a in self.registry.agents.values() if a.is_available()]

        # Apply specific agents filter (highest priority)
        if criteria.specific_agents:
            candidates = [a for a in candidates if a.name in criteria.specific_agents]

        # Apply exclusions
        if criteria.exclude_agents:
            candidates = [a for a in candidates if a.name not in criteria.exclude_agents]

        # Filter by contract analyzability
        candidates = [a for a in candidates if a.can_analyze(contract)]

        # Filter by language
        if criteria.language:
            candidates = [a for a in candidates
                         if criteria.language.lower() in
                         [lang.lower() for lang in a.supported_languages]]

        # Filter by capabilities
        if criteria.capabilities:
            candidates = [a for a in candidates
                         if any(cap in a.capabilities for cap in criteria.capabilities)]

        # Filter by cost
        if criteria.free_only:
            candidates = [a for a in candidates if a.cost == 0]
        elif criteria.max_cost is not None:
            candidates = [a for a in candidates if a.cost <= criteria.max_cost]

        # Filter by speed
        if criteria.max_speed:
            speed_order = {AgentSpeed.FAST: 0, AgentSpeed.MEDIUM: 1, AgentSpeed.SLOW: 2}
            max_speed_value = speed_order[criteria.max_speed]
            candidates = [a for a in candidates
                         if speed_order.get(a.speed, 999) <= max_speed_value]

        logger.info(f"Selected {len(candidates)} agents for analysis")
        for agent in candidates:
            logger.info(f"  • {agent.name} v{agent.version} (cost: ${agent.cost}, speed: {agent.speed.value})")

        return candidates

    def analyze(self,
                contract: str,
                agents: List[SecurityAgent],
                parallel: bool = True,
                timeout: Optional[float] = None,
                **agent_kwargs) -> OrchestrationResult:
        """
        Execute analysis with multiple agents.

        Args:
            contract: Path to contract file
            agents: List of agents to use
            parallel: Execute agents in parallel (default: True)
            timeout: Timeout per agent in seconds
            **agent_kwargs: Additional arguments to pass to agents

        Returns:
            OrchestrationResult with consolidated results
        """
        logger.info(f"Starting orchestrated analysis of {contract}")
        logger.info(f"Using {len(agents)} agents (parallel={parallel})")

        result = OrchestrationResult()
        start_time = time.time()

        if parallel:
            result = self._analyze_parallel(contract, agents, timeout, agent_kwargs)
        else:
            result = self._analyze_sequential(contract, agents, timeout, agent_kwargs)

        result.total_execution_time = time.time() - start_time

        logger.info(f"Analysis complete in {result.total_execution_time:.2f}s")
        logger.info(f"Success: {result.agents_success}/{result.agents_run} agents")

        return result

    def _analyze_parallel(self,
                         contract: str,
                         agents: List[SecurityAgent],
                         timeout: Optional[float],
                         agent_kwargs: Dict) -> OrchestrationResult:
        """Execute agents in parallel"""
        result = OrchestrationResult()

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents)) as executor:
            # Submit all agent tasks
            future_to_agent = {
                executor.submit(self._run_agent, agent, contract, timeout, agent_kwargs): agent
                for agent in agents
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_agent):
                agent = future_to_agent[future]
                try:
                    analysis_result = future.result()
                    result.add_result(agent.name, analysis_result, agent.cost)
                    logger.info(f"  ✓ {agent.name} completed ({analysis_result.status.value})")
                except Exception as e:
                    logger.error(f"  ✗ {agent.name} failed: {e}")
                    # Create error result
                    error_result = AnalysisResult(
                        agent=agent.name,
                        version=agent.version,
                        status=AnalysisStatus.ERROR,
                        timestamp=datetime.now(),
                        execution_time=0,
                        findings=[],
                        summary={},
                        error=str(e)
                    )
                    result.add_result(agent.name, error_result, 0)

        return result

    def _analyze_sequential(self,
                           contract: str,
                           agents: List[SecurityAgent],
                           timeout: Optional[float],
                           agent_kwargs: Dict) -> OrchestrationResult:
        """Execute agents sequentially"""
        result = OrchestrationResult()

        for agent in agents:
            logger.info(f"Running {agent.name}...")
            try:
                analysis_result = self._run_agent(agent, contract, timeout, agent_kwargs)
                result.add_result(agent.name, analysis_result, agent.cost)
                logger.info(f"  ✓ {agent.name} completed ({analysis_result.status.value})")
            except Exception as e:
                logger.error(f"  ✗ {agent.name} failed: {e}")
                error_result = AnalysisResult(
                    agent=agent.name,
                    version=agent.version,
                    status=AnalysisStatus.ERROR,
                    timestamp=datetime.now(),
                    execution_time=0,
                    findings=[],
                    summary={},
                    error=str(e)
                )
                result.add_result(agent.name, error_result, 0)

        return result

    def _run_agent(self,
                   agent: SecurityAgent,
                   contract: str,
                   timeout: Optional[float],
                   agent_kwargs: Dict) -> AnalysisResult:
        """Run a single agent with error handling and timeout support."""
        start_time = time.time()

        try:
            if timeout:
                # Execute with timeout using ThreadPoolExecutor
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(agent.analyze, contract, **agent_kwargs)
                    try:
                        result = future.result(timeout=timeout)
                    except concurrent.futures.TimeoutError:
                        logger.warning(
                            f"Agent {agent.name} timed out after {timeout}s"
                        )
                        return AnalysisResult(
                            agent=agent.name,
                            version=agent.version,
                            status=AnalysisStatus.TIMEOUT,
                            timestamp=datetime.now(),
                            execution_time=timeout,
                            findings=[],
                            summary={},
                            error=f"Analysis timed out after {timeout} seconds"
                        )
            else:
                result = agent.analyze(contract, **agent_kwargs)

            execution_time = time.time() - start_time
            result.execution_time = execution_time

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Agent {agent.name} failed: {e}", exc_info=True)

            return AnalysisResult(
                agent=agent.name,
                version=agent.version,
                status=AnalysisStatus.ERROR,
                timestamp=datetime.now(),
                execution_time=execution_time,
                findings=[],
                summary={},
                error=str(e)
            )

    def save_results(self, result: OrchestrationResult, output_dir: str):
        """
        Save orchestration results to disk.

        Args:
            result: OrchestrationResult to save
            output_dir: Directory to save results
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save individual agent results
        for agent_name, agent_result in result.results.items():
            if agent_result.status == AnalysisStatus.SUCCESS:
                # Save findings to agent-specific file
                agent_file = output_path / f"{agent_name}.txt"
                with open(agent_file, 'w') as f:
                    f.write(f"Agent: {agent_name} v{agent_result.version}\n")
                    f.write(f"Status: {agent_result.status.value}\n")
                    f.write(f"Execution Time: {agent_result.execution_time:.2f}s\n")
                    f.write(f"Findings: {len(agent_result.findings)}\n\n")

                    for i, finding in enumerate(agent_result.findings, 1):
                        f.write(f"Finding #{i}: {finding.type}\n")
                        f.write(f"Severity: {finding.severity.value}\n")
                        f.write(f"Location: {finding.location}\n")
                        f.write(f"Message: {finding.message}\n")
                        if finding.description:
                            f.write(f"Description: {finding.description}\n")
                        if finding.recommendation:
                            f.write(f"Recommendation: {finding.recommendation}\n")
                        f.write("\n")

        # Save summary
        summary_file = output_path / "orchestration_summary.txt"
        with open(summary_file, 'w') as f:
            summary = result.get_summary()
            f.write("MIESC Orchestrated Analysis Summary\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Agents Run: {summary['agents_run']}\n")
            f.write(f"Success: {summary['agents_success']}\n")
            f.write(f"Failed: {summary['agents_failed']}\n")
            f.write(f"Total Cost: ${summary['total_cost']:.2f}\n")
            f.write(f"Total Time: {summary['total_time']:.2f}s\n\n")
            f.write(f"Total Findings: {summary['total_findings']}\n")
            f.write(f"  Critical: {summary['severity_counts']['critical']}\n")
            f.write(f"  High: {summary['severity_counts']['high']}\n")
            f.write(f"  Medium: {summary['severity_counts']['medium']}\n")
            f.write(f"  Low: {summary['severity_counts']['low']}\n")
            f.write(f"  Info: {summary['severity_counts']['info']}\n")

        logger.info(f"Results saved to {output_path}")

    def get_available_agents(self) -> List[str]:
        """Get list of available agent names"""
        if not self._initialized:
            self.initialize()
        return [a.name for a in self.registry.agents.values() if a.is_available()]

    def get_agent_info(self, agent_name: str) -> Optional[Dict]:
        """Get detailed info about an agent"""
        agent = self.registry.get(agent_name)
        if not agent:
            return None

        metadata = agent.get_metadata()
        return {
            'name': metadata.name,
            'version': metadata.version,
            'description': metadata.description,
            'author': metadata.author,
            'license': metadata.license,
            'capabilities': [cap.value for cap in metadata.capabilities],
            'languages': metadata.supported_languages,
            'cost': metadata.cost,
            'speed': metadata.speed.value,
            'available': agent.is_available(),
            'homepage': metadata.homepage,
            'repository': metadata.repository
        }
