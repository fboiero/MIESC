"""
Surya Visualization and Metrics Tool Integration
Provides contract visualization, call graphs, and complexity metrics.
"""
import subprocess
import logging
import json
import os
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_surya_installed():
    """Check if Surya is installed."""
    try:
        subprocess.run(['surya', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("Surya not found. Install with: npm install -g surya")
        return False


def generate_call_graph(contract_path, output_dir='analysis/surya/outputs'):
    """
    Generate call graph visualization for a contract.

    Args:
        contract_path (str): Path to Solidity contract
        output_dir (str): Directory for output files

    Returns:
        dict: Paths to generated files
    """
    if not check_surya_installed():
        return {'error': 'Surya not installed'}

    try:
        os.makedirs(output_dir, exist_ok=True)
        contract_name = Path(contract_path).stem
        output_dot = f"{output_dir}/{contract_name}_graph.dot"

        logger.info(f"Generating call graph for {contract_path}")

        # Generate graph in DOT format
        result = subprocess.run(
            ['surya', 'graph', contract_path],
            capture_output=True,
            text=True,
            check=True
        )

        # Save DOT file
        with open(output_dot, 'w') as f:
            f.write(result.stdout)

        logger.info(f"Call graph saved to {output_dot}")

        # Intentar convertir a PNG con graphviz (si está disponible)
        output_png = f"{output_dir}/{contract_name}_graph.png"
        try:
            subprocess.run(
                ['dot', '-Tpng', output_dot, '-o', output_png],
                check=True,
                timeout=30
            )
            logger.info(f"PNG graph saved to {output_png}")
            return {
                'dot': output_dot,
                'png': output_png,
                'status': 'success'
            }
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("graphviz not installed, PNG not generated")
            return {
                'dot': output_dot,
                'status': 'dot_only'
            }

    except Exception as e:
        logger.error(f"Error generating call graph: {e}")
        return {'error': str(e), 'status': 'error'}


def generate_inheritance_tree(contract_path, output_dir='analysis/surya/outputs'):
    """
    Generate inheritance tree visualization.

    Args:
        contract_path (str): Path to Solidity contract
        output_dir (str): Directory for output files

    Returns:
        dict: Paths to generated files
    """
    if not check_surya_installed():
        return {'error': 'Surya not installed'}

    try:
        os.makedirs(output_dir, exist_ok=True)
        contract_name = Path(contract_path).stem
        output_file = f"{output_dir}/{contract_name}_inheritance.txt"

        logger.info(f"Generating inheritance tree for {contract_path}")

        result = subprocess.run(
            ['surya', 'inheritance', contract_path],
            capture_output=True,
            text=True,
            check=True
        )

        with open(output_file, 'w') as f:
            f.write(result.stdout)

        logger.info(f"Inheritance tree saved to {output_file}")
        return {
            'file': output_file,
            'content': result.stdout,
            'status': 'success'
        }

    except Exception as e:
        logger.error(f"Error generating inheritance tree: {e}")
        return {'error': str(e), 'status': 'error'}


def analyze_complexity(contract_path, output_dir='analysis/surya/outputs'):
    """
    Analyze contract complexity and generate metrics.

    Args:
        contract_path (str): Path to Solidity contract
        output_dir (str): Directory for output files

    Returns:
        dict: Complexity metrics
    """
    if not check_surya_installed():
        return {'error': 'Surya not installed'}

    try:
        os.makedirs(output_dir, exist_ok=True)
        contract_name = Path(contract_path).stem

        logger.info(f"Analyzing complexity for {contract_path}")

        # Parse contract
        result = subprocess.run(
            ['surya', 'parse', contract_path],
            capture_output=True,
            text=True,
            check=True
        )

        parse_output = f"{output_dir}/{contract_name}_parse.txt"
        with open(parse_output, 'w') as f:
            f.write(result.stdout)

        # Describe contract
        result = subprocess.run(
            ['surya', 'describe', contract_path],
            capture_output=True,
            text=True,
            check=True
        )

        describe_output = f"{output_dir}/{contract_name}_describe.txt"
        with open(describe_output, 'w') as f:
            f.write(result.stdout)

        # Parse metrics from output
        metrics = parse_describe_output(result.stdout)
        metrics['parse_file'] = parse_output
        metrics['describe_file'] = describe_output
        metrics['status'] = 'success'

        logger.info(f"Complexity analysis completed")
        return metrics

    except Exception as e:
        logger.error(f"Error analyzing complexity: {e}")
        return {'error': str(e), 'status': 'error'}


def parse_describe_output(output):
    """
    Parse Surya describe output to extract metrics.

    Args:
        output (str): Surya describe output

    Returns:
        dict: Extracted metrics
    """
    metrics = {
        'contracts': [],
        'total_functions': 0,
        'total_modifiers': 0,
        'total_lines': 0
    }

    lines = output.split('\n')
    current_contract = None

    for line in lines:
        # Detectar nuevo contrato
        if '│' in line and 'Contract' in line:
            if current_contract:
                metrics['contracts'].append(current_contract)
            current_contract = {
                'name': '',
                'type': '',
                'functions': 0,
                'modifiers': 0
            }

        # Contar funciones
        if 'Function' in line:
            metrics['total_functions'] += 1
            if current_contract:
                current_contract['functions'] += 1

        # Contar modifiers
        if 'Modifier' in line:
            metrics['total_modifiers'] += 1
            if current_contract:
                current_contract['modifiers'] += 1

    if current_contract:
        metrics['contracts'].append(current_contract)

    return metrics


def generate_dependencies(contract_path, output_dir='analysis/surya/outputs'):
    """
    Generate dependency graph.

    Args:
        contract_path (str): Path to Solidity contract
        output_dir (str): Directory for output files

    Returns:
        dict: Dependency information
    """
    if not check_surya_installed():
        return {'error': 'Surya not installed'}

    try:
        os.makedirs(output_dir, exist_ok=True)
        contract_name = Path(contract_path).stem
        output_file = f"{output_dir}/{contract_name}_dependencies.txt"

        logger.info(f"Analyzing dependencies for {contract_path}")

        result = subprocess.run(
            ['surya', 'dependencies', contract_path],
            capture_output=True,
            text=True,
            check=True
        )

        with open(output_file, 'w') as f:
            f.write(result.stdout)

        logger.info(f"Dependencies saved to {output_file}")
        return {
            'file': output_file,
            'content': result.stdout,
            'status': 'success'
        }

    except Exception as e:
        logger.error(f"Error analyzing dependencies: {e}")
        return {'error': str(e), 'status': 'error'}


def full_analysis(contract_path, output_dir='analysis/surya/outputs'):
    """
    Perform complete Surya analysis: graphs, metrics, dependencies.

    Args:
        contract_path (str): Path to Solidity contract
        output_dir (str): Directory for output files

    Returns:
        dict: Complete analysis results
    """
    logger.info(f"Starting full Surya analysis for {contract_path}")

    results = {
        'contract': contract_path,
        'call_graph': generate_call_graph(contract_path, output_dir),
        'inheritance': generate_inheritance_tree(contract_path, output_dir),
        'complexity': analyze_complexity(contract_path, output_dir),
        'dependencies': generate_dependencies(contract_path, output_dir),
        'status': 'completed'
    }

    logger.info("Full Surya analysis completed")
    return results


if __name__ == "__main__":
    # Test básico
    import sys

    if len(sys.argv) < 2:
        print("Usage: python surya_tool.py <contract_path>")
        sys.exit(1)

    contract = sys.argv[1]
    results = full_analysis(contract)

    print("\n=== SURYA ANALYSIS RESULTS ===")
    print(json.dumps(results, indent=2, default=str))
