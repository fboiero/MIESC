"""
MIESC Agent Registry
====================

Registry and discovery system for security agents.
Supports dynamic loading from multiple sources.
"""

import importlib
import importlib.util
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set
import inspect

from src.core.agent_protocol import SecurityAgent, AgentMetadata

logger = logging.getLogger(__name__)


class AgentRegistry:
    """
    Central registry for security agents.

    Discovers and manages agents from:
    1. Built-in agents (src/agents/)
    2. User plugins (~/.miesc/agents/)
    3. Project plugins (./plugins/agents/)
    4. MCP servers (if available)
    """

    def __init__(self):
        self.agents: Dict[str, SecurityAgent] = {}
        self._plugin_dirs: List[Path] = []
        self._init_plugin_dirs()

    def _init_plugin_dirs(self):
        """Initialize plugin directory paths"""
        # User plugin directory
        user_dir = Path.home() / '.miesc' / 'agents'
        user_dir.mkdir(parents=True, exist_ok=True)
        self._plugin_dirs.append(user_dir)

        # Project plugin directory
        project_dir = Path.cwd() / 'plugins' / 'agents'
        if project_dir.exists():
            self._plugin_dirs.append(project_dir)

        # Built-in agents directory
        builtin_dir = Path(__file__).parent.parent / 'agents'
        if builtin_dir.exists():
            self._plugin_dirs.append(builtin_dir)

    def register(self, agent: SecurityAgent, force: bool = False) -> bool:
        """
        Register an agent instance.

        Args:
            agent: Agent instance to register
            force: Overwrite if already registered

        Returns:
            bool: True if registered successfully

        Raises:
            ValueError: If agent name already exists and force=False
            TypeError: If agent doesn't implement SecurityAgent
        """
        if not isinstance(agent, SecurityAgent):
            raise TypeError(f"Agent must implement SecurityAgent protocol, got {type(agent)}")

        # Validate agent implementation
        if not agent.validate():
            raise ValueError(f"Agent {agent.name} failed validation")

        # Check for duplicates
        if agent.name in self.agents and not force:
            raise ValueError(f"Agent '{agent.name}' is already registered. Use force=True to overwrite.")

        self.agents[agent.name] = agent
        logger.info(f"Registered agent: {agent.name} v{agent.version}")
        return True

    def unregister(self, agent_name: str) -> bool:
        """
        Unregister an agent.

        Args:
            agent_name: Name of agent to remove

        Returns:
            bool: True if agent was removed
        """
        if agent_name in self.agents:
            del self.agents[agent_name]
            logger.info(f"Unregistered agent: {agent_name}")
            return True
        return False

    def get(self, agent_name: str) -> Optional[SecurityAgent]:
        """
        Get agent by name.

        Args:
            agent_name: Name of the agent

        Returns:
            SecurityAgent instance or None
        """
        return self.agents.get(agent_name)

    def list_agents(self, available_only: bool = False) -> List[AgentMetadata]:
        """
        List all registered agents.

        Args:
            available_only: Only include agents that are currently available

        Returns:
            List of agent metadata
        """
        agents = self.agents.values()

        if available_only:
            agents = [a for a in agents if a.is_available()]

        return [agent.get_metadata() for agent in agents]

    def discover_all(self) -> Dict[str, SecurityAgent]:
        """
        Discover all available agents from all sources.

        Returns:
            Dict mapping agent names to instances
        """
        logger.info("Starting agent discovery...")

        # Discover from all plugin directories
        for plugin_dir in self._plugin_dirs:
            if plugin_dir.exists():
                logger.info(f"Scanning directory: {plugin_dir}")
                discovered = self._discover_from_directory(plugin_dir)
                logger.info(f"  Found {len(discovered)} agents")

        logger.info(f"Discovery complete. Total agents: {len(self.agents)}")
        return self.agents

    def _discover_from_directory(self, directory: Path) -> Dict[str, SecurityAgent]:
        """
        Discover agents from a directory.

        Args:
            directory: Path to scan for agent modules

        Returns:
            Dict of discovered agents
        """
        discovered = {}

        # Find all Python files
        for agent_file in directory.glob('*_agent.py'):
            try:
                # Skip __init__.py and non-agent files
                if agent_file.name == '__init__.py':
                    continue

                logger.debug(f"Loading module: {agent_file}")
                agents_found = self._load_agents_from_file(agent_file)

                for agent in agents_found:
                    try:
                        self.register(agent, force=False)
                        discovered[agent.name] = agent
                    except ValueError as e:
                        logger.warning(f"Skipping agent from {agent_file}: {e}")

            except Exception as e:
                logger.error(f"Failed to load agents from {agent_file}: {e}", exc_info=True)

        return discovered

    def _load_agents_from_file(self, file_path: Path) -> List[SecurityAgent]:
        """
        Load agent classes from a Python file.

        Args:
            file_path: Path to Python module

        Returns:
            List of agent instances
        """
        agents = []

        try:
            # Load module dynamically
            module_name = file_path.stem
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec is None or spec.loader is None:
                logger.warning(f"Could not load spec for {file_path}")
                return agents

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            # Find SecurityAgent subclasses
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Check if it's a SecurityAgent subclass (but not SecurityAgent itself)
                if (issubclass(obj, SecurityAgent) and
                    obj is not SecurityAgent and
                    obj.__module__ == module_name):

                    try:
                        # Instantiate the agent
                        agent_instance = obj()
                        agents.append(agent_instance)
                        logger.debug(f"  Loaded agent class: {name}")
                    except Exception as e:
                        logger.warning(f"  Failed to instantiate {name}: {e}")

        except Exception as e:
            logger.error(f"Error loading module {file_path}: {e}", exc_info=True)

        return agents

    def filter_agents(self,
                     language: Optional[str] = None,
                     capability: Optional[str] = None,
                     free_only: bool = False,
                     available_only: bool = True,
                     max_speed: Optional[str] = None) -> List[SecurityAgent]:
        """
        Filter agents by criteria.

        Args:
            language: Filter by supported language (e.g., "solidity")
            capability: Filter by capability (e.g., "static_analysis")
            free_only: Only include free agents (cost = 0)
            available_only: Only include available agents
            max_speed: Maximum speed ("fast", "medium", "slow")

        Returns:
            List of matching agents
        """
        filtered = list(self.agents.values())

        # Filter by availability
        if available_only:
            filtered = [a for a in filtered if a.is_available()]

        # Filter by language
        if language:
            filtered = [a for a in filtered if language.lower() in
                       [lang.lower() for lang in a.supported_languages]]

        # Filter by capability
        if capability:
            from src.core.agent_protocol import AgentCapability
            try:
                cap = AgentCapability(capability.lower())
                filtered = [a for a in filtered if cap in a.capabilities]
            except ValueError:
                logger.warning(f"Unknown capability: {capability}")

        # Filter by cost
        if free_only:
            filtered = [a for a in filtered if a.cost == 0]

        # Filter by speed
        if max_speed:
            from src.core.agent_protocol import AgentSpeed
            speed_order = {AgentSpeed.FAST: 0, AgentSpeed.MEDIUM: 1, AgentSpeed.SLOW: 2}
            try:
                max_speed_enum = AgentSpeed(max_speed.lower())
                max_speed_value = speed_order[max_speed_enum]
                filtered = [a for a in filtered
                           if speed_order[a.speed] <= max_speed_value]
            except (ValueError, KeyError):
                logger.warning(f"Unknown speed: {max_speed}")

        return filtered

    def get_statistics(self) -> Dict[str, any]:
        """
        Get registry statistics.

        Returns:
            Dict with statistics
        """
        total = len(self.agents)
        available = len([a for a in self.agents.values() if a.is_available()])
        free = len([a for a in self.agents.values() if a.cost == 0])

        # Count by capability
        from src.core.agent_protocol import AgentCapability
        capabilities = {}
        for cap in AgentCapability:
            count = len([a for a in self.agents.values() if cap in a.capabilities])
            if count > 0:
                capabilities[cap.value] = count

        # Count by language
        languages = {}
        for agent in self.agents.values():
            for lang in agent.supported_languages:
                languages[lang] = languages.get(lang, 0) + 1

        return {
            'total_agents': total,
            'available_agents': available,
            'free_agents': free,
            'paid_agents': total - free,
            'capabilities': capabilities,
            'languages': languages
        }

    def validate_all(self) -> Dict[str, bool]:
        """
        Validate all registered agents.

        Returns:
            Dict mapping agent names to validation results
        """
        results = {}
        for name, agent in self.agents.items():
            try:
                results[name] = agent.validate()
            except Exception as e:
                logger.error(f"Validation error for {name}: {e}")
                results[name] = False
        return results

    def __len__(self) -> int:
        """Number of registered agents"""
        return len(self.agents)

    def __contains__(self, agent_name: str) -> bool:
        """Check if agent is registered"""
        return agent_name in self.agents

    def __iter__(self):
        """Iterate over agent names"""
        return iter(self.agents)

    def __repr__(self) -> str:
        return f"<AgentRegistry: {len(self.agents)} agents>"
