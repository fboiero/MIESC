#!/usr/bin/env python3
"""
MIESC - Project Analyzer
Analyzes multi-contract projects from folders or GitHub repositories
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Set, Tuple
import subprocess
import tempfile
import shutil


class ContractInfo:
    """Information about a Solidity contract"""

    def __init__(self, path: str, name: str):
        self.path = path
        self.name = name
        self.imports: Set[str] = set()
        self.inherits_from: Set[str] = set()
        self.interfaces: Set[str] = set()
        self.libraries: Set[str] = set()
        self.pragma_version = ""
        self.is_interface = False
        self.is_library = False
        self.is_abstract = False
        self.lines_of_code = 0
        self.functions_count = 0

    def to_dict(self):
        return {
            'path': self.path,
            'name': self.name,
            'imports': list(self.imports),
            'inherits_from': list(self.inherits_from),
            'interfaces': list(self.interfaces),
            'libraries': list(self.libraries),
            'pragma_version': self.pragma_version,
            'is_interface': self.is_interface,
            'is_library': self.is_library,
            'is_abstract': self.is_abstract,
            'lines_of_code': self.lines_of_code,
            'functions_count': self.functions_count
        }


class ProjectAnalyzer:
    """Analyzes Solidity projects from folders or GitHub"""

    def __init__(self, source: str):
        """
        Initialize project analyzer

        Args:
            source: Can be:
                - Local file path (e.g., "contract.sol")
                - Local directory (e.g., "contracts/")
                - GitHub URL (e.g., "https://github.com/user/repo")
        """
        self.source = source
        self.temp_dir = None
        self.contracts: Dict[str, ContractInfo] = {}
        self.analysis_strategy = "scan_all"  # or "unified"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        """Clean up temporary directories"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def is_github_url(self, source: str) -> bool:
        """Check if source is a GitHub URL"""
        return source.startswith('http') and 'github.com' in source

    def clone_github_repo(self, url: str) -> str:
        """
        Clone GitHub repository to temporary directory

        Args:
            url: GitHub repository URL

        Returns:
            Path to cloned repository
        """
        self.temp_dir = tempfile.mkdtemp(prefix='miesc_github_')

        try:
            # Clone with depth=1 for faster download
            subprocess.run(
                ['git', 'clone', '--depth', '1', url, self.temp_dir],
                check=True,
                capture_output=True,
                text=True
            )
            return self.temp_dir
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to clone repository: {e.stderr}")

    def find_solidity_files(self, directory: str) -> List[str]:
        """
        Find all Solidity files in directory

        Args:
            directory: Path to directory

        Returns:
            List of .sol file paths
        """
        sol_files = []
        for root, dirs, files in os.walk(directory):
            # Skip common non-contract directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'test', 'tests', '__pycache__']]

            for file in files:
                if file.endswith('.sol'):
                    sol_files.append(os.path.join(root, file))

        return sorted(sol_files)

    def parse_contract(self, file_path: str) -> ContractInfo:
        """
        Parse a Solidity contract file

        Args:
            file_path: Path to .sol file

        Returns:
            ContractInfo object
        """
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Extract contract name from file
        contract_name = Path(file_path).stem
        info = ContractInfo(file_path, contract_name)

        # Count lines of code (excluding comments and empty lines)
        lines = content.split('\n')
        info.lines_of_code = len([l for l in lines if l.strip() and not l.strip().startswith('//')])

        # Extract pragma version
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', content)
        if pragma_match:
            info.pragma_version = pragma_match.group(1).strip()

        # Extract imports
        imports = re.findall(r'import\s+["\']([^"\']+)["\']', content)
        info.imports = set(imports)

        # Extract contract declarations
        contract_decl = re.search(
            r'(interface|library|abstract\s+contract|contract)\s+(\w+)(?:\s+is\s+([^{]+))?',
            content
        )

        if contract_decl:
            contract_type = contract_decl.group(1).strip()
            info.name = contract_decl.group(2).strip()

            info.is_interface = 'interface' in contract_type
            info.is_library = 'library' in contract_type
            info.is_abstract = 'abstract' in contract_type

            # Extract inheritance
            if contract_decl.group(3):
                parents = contract_decl.group(3).strip().split(',')
                for parent in parents:
                    parent = parent.strip().split('(')[0].strip()  # Remove constructor args
                    info.inherits_from.add(parent)

        # Count functions
        info.functions_count = len(re.findall(r'function\s+\w+\s*\(', content))

        return info

    def analyze_project(self) -> Dict:
        """
        Analyze the project structure

        Returns:
            Dictionary with project analysis
        """
        # Determine source type and get directory
        if os.path.isfile(self.source):
            # Single file
            contract = self.parse_contract(self.source)
            self.contracts[contract.name] = contract
            project_dir = os.path.dirname(self.source)

        elif os.path.isdir(self.source):
            # Local directory
            project_dir = self.source
            sol_files = self.find_solidity_files(project_dir)

            for file_path in sol_files:
                contract = self.parse_contract(file_path)
                self.contracts[contract.name] = contract

        elif self.is_github_url(self.source):
            # GitHub repository
            project_dir = self.clone_github_repo(self.source)
            sol_files = self.find_solidity_files(project_dir)

            for file_path in sol_files:
                contract = self.parse_contract(file_path)
                self.contracts[contract.name] = contract

        else:
            raise ValueError(f"Invalid source: {self.source}")

        # Build dependency graph
        dependency_graph = self.build_dependency_graph()

        # Calculate statistics
        stats = self.calculate_statistics()

        return {
            'source': self.source,
            'project_dir': project_dir,
            'total_contracts': len(self.contracts),
            'contracts': {name: contract.to_dict() for name, contract in self.contracts.items()},
            'dependency_graph': dependency_graph,
            'statistics': stats
        }

    def build_dependency_graph(self) -> Dict:
        """
        Build dependency graph between contracts

        Returns:
            Dictionary with nodes and edges
        """
        nodes = []
        edges = []

        for name, contract in self.contracts.items():
            # Add node
            node = {
                'id': name,
                'label': name,
                'type': 'interface' if contract.is_interface else 'library' if contract.is_library else 'contract',
                'lines': contract.lines_of_code,
                'functions': contract.functions_count
            }
            nodes.append(node)

            # Add edges for inheritance
            for parent in contract.inherits_from:
                edges.append({
                    'from': name,
                    'to': parent,
                    'type': 'inherits',
                    'label': 'inherits'
                })

            # Add edges for imports (if the imported contract is in our project)
            for imp in contract.imports:
                # Extract contract name from import path
                imported_name = Path(imp).stem
                if imported_name in self.contracts:
                    edges.append({
                        'from': name,
                        'to': imported_name,
                        'type': 'imports',
                        'label': 'imports'
                    })

        return {
            'nodes': nodes,
            'edges': edges
        }

    def calculate_statistics(self) -> Dict:
        """Calculate project statistics"""
        stats = {
            'total_files': len(self.contracts),
            'total_lines': sum(c.lines_of_code for c in self.contracts.values()),
            'total_functions': sum(c.functions_count for c in self.contracts.values()),
            'interfaces': sum(1 for c in self.contracts.values() if c.is_interface),
            'libraries': sum(1 for c in self.contracts.values() if c.is_library),
            'contracts': sum(1 for c in self.contracts.values() if not c.is_interface and not c.is_library),
            'pragma_versions': list(set(c.pragma_version for c in self.contracts.values() if c.pragma_version)),
            'avg_lines_per_contract': 0,
            'avg_functions_per_contract': 0
        }

        if stats['total_files'] > 0:
            stats['avg_lines_per_contract'] = stats['total_lines'] / stats['total_files']
            stats['avg_functions_per_contract'] = stats['total_functions'] / stats['total_files']

        return stats

    def get_scan_plan(self) -> List[Dict]:
        """
        Generate a scan plan for all contracts

        Returns:
            List of contracts to scan with metadata
        """
        # Topological sort to scan dependencies first
        sorted_contracts = self.topological_sort()

        scan_plan = []
        for contract_name in sorted_contracts:
            contract = self.contracts[contract_name]

            plan_item = {
                'name': contract.name,
                'path': contract.path,
                'order': len(scan_plan) + 1,
                'dependencies': list(contract.inherits_from),
                'lines': contract.lines_of_code,
                'priority': self.calculate_priority(contract),
                'estimated_time_seconds': self.estimate_analysis_time(contract)
            }
            scan_plan.append(plan_item)

        return scan_plan

    def topological_sort(self) -> List[str]:
        """
        Sort contracts in dependency order (dependencies first)

        Returns:
            List of contract names in scan order
        """
        # Build adjacency list
        in_degree = {name: 0 for name in self.contracts.keys()}
        adj_list = {name: [] for name in self.contracts.keys()}

        for name, contract in self.contracts.items():
            for parent in contract.inherits_from:
                if parent in self.contracts:
                    adj_list[parent].append(name)
                    in_degree[name] += 1

        # Kahn's algorithm
        queue = [name for name, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            node = queue.pop(0)
            result.append(node)

            for neighbor in adj_list[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # If not all nodes processed, there's a cycle - return as is
        if len(result) != len(self.contracts):
            return list(self.contracts.keys())

        return result

    def calculate_priority(self, contract: ContractInfo) -> str:
        """
        Calculate scan priority based on contract characteristics

        Returns:
            'high', 'medium', or 'low'
        """
        # High priority: large contracts, non-libraries, many functions
        if contract.is_library or contract.is_interface:
            return 'low'

        if contract.lines_of_code > 200 or contract.functions_count > 10:
            return 'high'

        if contract.lines_of_code > 100 or contract.functions_count > 5:
            return 'medium'

        return 'low'

    def estimate_analysis_time(self, contract: ContractInfo) -> int:
        """
        Estimate analysis time in seconds

        Args:
            contract: Contract to analyze

        Returns:
            Estimated seconds
        """
        # Base time
        base_time = 30

        # Add time based on lines of code
        time_per_100_lines = 10
        lines_time = (contract.lines_of_code / 100) * time_per_100_lines

        # Add time based on functions
        time_per_function = 2
        functions_time = contract.functions_count * time_per_function

        return int(base_time + lines_time + functions_time)

    def create_unified_contract(self, output_path: str) -> str:
        """
        Combine all contracts into a single file

        Args:
            output_path: Path to save unified contract

        Returns:
            Path to unified contract
        """
        # Get contracts in dependency order
        sorted_contracts = self.topological_sort()

        unified_content = []
        unified_content.append("// MIESC - Unified Contract Analysis")
        unified_content.append("// This file combines multiple contracts for analysis")
        unified_content.append("// Generated automatically - DO NOT EDIT")
        unified_content.append("")

        # Get most recent pragma version
        pragma_versions = [c.pragma_version for c in self.contracts.values() if c.pragma_version]
        if pragma_versions:
            pragma = pragma_versions[-1]  # Use last version
            unified_content.append(f"pragma solidity {pragma};")
            unified_content.append("")

        # Add all contracts
        processed_imports = set()

        for contract_name in sorted_contracts:
            contract = self.contracts[contract_name]

            unified_content.append(f"// ===== {contract.name} =====")
            unified_content.append(f"// Source: {contract.path}")
            unified_content.append("")

            with open(contract.path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Remove pragma statements (already at top)
            content = re.sub(r'pragma\s+solidity\s+[^;]+;', '', content)

            # Process imports (avoid duplicates)
            import_lines = []
            other_lines = []

            for line in content.split('\n'):
                if line.strip().startswith('import'):
                    if line not in processed_imports:
                        processed_imports.add(line)
                        import_lines.append(line)
                else:
                    other_lines.append(line)

            # Add imports first, then contract code
            if import_lines:
                unified_content.extend(import_lines)
                unified_content.append("")

            unified_content.extend(other_lines)
            unified_content.append("")
            unified_content.append("")

        # Write unified contract
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unified_content))

        return output_path


def main():
    """Test project analyzer"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python project_analyzer.py <source>")
        print("  source: file path, directory, or GitHub URL")
        sys.exit(1)

    source = sys.argv[1]

    print(f"Analyzing: {source}")
    print("=" * 60)

    with ProjectAnalyzer(source) as analyzer:
        # Analyze project
        analysis = analyzer.analyze_project()

        # Print statistics
        stats = analysis['statistics']
        print(f"\nProject Statistics:")
        print(f"  Total contracts: {stats['total_files']}")
        print(f"  Total lines: {stats['total_lines']}")
        print(f"  Total functions: {stats['total_functions']}")
        print(f"  Interfaces: {stats['interfaces']}")
        print(f"  Libraries: {stats['libraries']}")
        print(f"  Contracts: {stats['contracts']}")

        # Print dependency graph
        graph = analysis['dependency_graph']
        print(f"\nDependency Graph:")
        print(f"  Nodes: {len(graph['nodes'])}")
        print(f"  Edges: {len(graph['edges'])}")

        # Print scan plan
        scan_plan = analyzer.get_scan_plan()
        print(f"\nScan Plan ({len(scan_plan)} contracts):")
        for item in scan_plan[:5]:  # Show first 5
            print(f"  {item['order']}. {item['name']} - {item['priority']} priority ({item['estimated_time_seconds']}s)")

        if len(scan_plan) > 5:
            print(f"  ... and {len(scan_plan) - 5} more")


if __name__ == '__main__':
    main()
