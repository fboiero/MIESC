"""
MIESC WebSocket API - Real-time Analysis Server.

Provides WebSocket endpoints for:
- Real-time contract analysis with progress updates
- Live notifications for findings
- Streaming results as tools complete

Based on Flask-SocketIO for WebSocket support.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-12-03
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from typing import Dict, Any, Optional

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core import get_ml_orchestrator, get_tool_discovery, HealthChecker

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('MIESC_SECRET_KEY', 'miesc-websocket-secret-2025')
CORS(app, resources={r"/*": {"origins": "*"}})

# Initialize SocketIO with async mode
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25
)

# Global state
active_analyses: Dict[str, Dict[str, Any]] = {}
connected_clients: Dict[str, str] = {}  # sid -> room

MIESC_VERSION = "4.0.0"


# =============================================================================
# WebSocket Event Handlers
# =============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    client_id = request.sid
    connected_clients[client_id] = None
    emit('connected', {
        'status': 'connected',
        'client_id': client_id,
        'server': 'MIESC WebSocket API',
        'version': MIESC_VERSION,
        'timestamp': datetime.now().isoformat()
    })
    print(f"[WS] Client connected: {client_id}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    client_id = request.sid
    if client_id in connected_clients:
        del connected_clients[client_id]
    print(f"[WS] Client disconnected: {client_id}")


@socketio.on('join_analysis')
def handle_join_analysis(data):
    """Join an analysis room to receive updates."""
    analysis_id = data.get('analysis_id')
    if analysis_id:
        join_room(analysis_id)
        connected_clients[request.sid] = analysis_id
        emit('joined', {
            'analysis_id': analysis_id,
            'status': 'subscribed'
        })


@socketio.on('leave_analysis')
def handle_leave_analysis(data):
    """Leave an analysis room."""
    analysis_id = data.get('analysis_id')
    if analysis_id:
        leave_room(analysis_id)
        connected_clients[request.sid] = None
        emit('left', {'analysis_id': analysis_id})


@socketio.on('start_analysis')
def handle_start_analysis(data):
    """Start a new contract analysis with real-time updates."""
    contract_path = data.get('contract_path')
    scan_type = data.get('scan_type', 'quick')  # quick, full, deep
    timeout = data.get('timeout', 300)

    if not contract_path:
        emit('error', {'message': 'contract_path is required'})
        return

    if not os.path.exists(contract_path):
        emit('error', {'message': f'Contract not found: {contract_path}'})
        return

    # Generate analysis ID
    analysis_id = f"analysis_{int(time.time() * 1000)}"

    # Store analysis state
    active_analyses[analysis_id] = {
        'id': analysis_id,
        'contract_path': contract_path,
        'scan_type': scan_type,
        'status': 'started',
        'progress': 0,
        'started_at': datetime.now().isoformat(),
        'findings': [],
        'tools_completed': [],
        'tools_pending': []
    }

    # Join the analysis room
    join_room(analysis_id)
    connected_clients[request.sid] = analysis_id

    # Emit start confirmation
    emit('analysis_started', {
        'analysis_id': analysis_id,
        'contract_path': contract_path,
        'scan_type': scan_type,
        'status': 'running'
    })

    # Start analysis in background thread
    thread = threading.Thread(
        target=run_analysis_with_updates,
        args=(analysis_id, contract_path, scan_type, timeout)
    )
    thread.daemon = True
    thread.start()


@socketio.on('get_analysis_status')
def handle_get_status(data):
    """Get current status of an analysis."""
    analysis_id = data.get('analysis_id')

    if analysis_id in active_analyses:
        emit('analysis_status', active_analyses[analysis_id])
    else:
        emit('error', {'message': f'Analysis not found: {analysis_id}'})


@socketio.on('cancel_analysis')
def handle_cancel_analysis(data):
    """Cancel a running analysis."""
    analysis_id = data.get('analysis_id')

    if analysis_id in active_analyses:
        active_analyses[analysis_id]['status'] = 'cancelled'
        socketio.emit('analysis_cancelled', {
            'analysis_id': analysis_id,
            'status': 'cancelled'
        }, room=analysis_id)
    else:
        emit('error', {'message': f'Analysis not found: {analysis_id}'})


# =============================================================================
# Analysis Runner with Real-time Updates
# =============================================================================

def run_analysis_with_updates(
    analysis_id: str,
    contract_path: str,
    scan_type: str,
    timeout: int
):
    """Run analysis and emit real-time updates via WebSocket."""
    try:
        orchestrator = get_ml_orchestrator()
        discovery = get_tool_discovery()

        # Get available tools
        tools = discovery.get_available_tools()
        tool_names = [t.name for t in tools if hasattr(t, 'name')]

        active_analyses[analysis_id]['tools_pending'] = tool_names.copy()

        # Emit tool list
        socketio.emit('tools_discovered', {
            'analysis_id': analysis_id,
            'tools': tool_names,
            'count': len(tool_names)
        }, room=analysis_id)

        # Progress tracking
        total_tools = max(len(tool_names), 1)
        completed = 0

        def emit_progress(tool_name: str, status: str, findings: list = None):
            nonlocal completed

            if status == 'completed':
                completed += 1
                if tool_name in active_analyses[analysis_id]['tools_pending']:
                    active_analyses[analysis_id]['tools_pending'].remove(tool_name)
                active_analyses[analysis_id]['tools_completed'].append(tool_name)

            progress = int((completed / total_tools) * 100)
            active_analyses[analysis_id]['progress'] = progress

            update = {
                'analysis_id': analysis_id,
                'tool': tool_name,
                'status': status,
                'progress': progress,
                'findings_count': len(findings) if findings else 0
            }

            socketio.emit('tool_update', update, room=analysis_id)

            if findings:
                for finding in findings:
                    socketio.emit('finding_discovered', {
                        'analysis_id': analysis_id,
                        'tool': tool_name,
                        'finding': finding
                    }, room=analysis_id)
                    active_analyses[analysis_id]['findings'].append(finding)

        # Emit start of each tool (simulated - real implementation would hook into adapters)
        for tool in tool_names[:5]:  # Limit for demo
            if active_analyses[analysis_id]['status'] == 'cancelled':
                break

            emit_progress(tool, 'running')
            time.sleep(0.5)  # Simulate tool startup

        # Run actual analysis
        if scan_type == 'quick':
            result = orchestrator.quick_scan(contract_path, timeout=timeout)
        elif scan_type == 'deep':
            result = orchestrator.deep_scan(contract_path, timeout=timeout)
        else:
            result = orchestrator.analyze(contract_path, timeout=timeout)

        # Get summary
        summary = result.get_summary() if hasattr(result, 'get_summary') else {}

        # Emit final results
        active_analyses[analysis_id]['status'] = 'completed'
        active_analyses[analysis_id]['progress'] = 100
        active_analyses[analysis_id]['completed_at'] = datetime.now().isoformat()
        active_analyses[analysis_id]['summary'] = summary

        socketio.emit('analysis_completed', {
            'analysis_id': analysis_id,
            'status': 'completed',
            'summary': summary,
            'total_findings': summary.get('total_findings', 0),
            'risk_level': summary.get('risk_level', 'UNKNOWN'),
            'execution_time_ms': result.execution_time_ms if hasattr(result, 'execution_time_ms') else 0
        }, room=analysis_id)

    except Exception as e:
        active_analyses[analysis_id]['status'] = 'error'
        active_analyses[analysis_id]['error'] = str(e)

        socketio.emit('analysis_error', {
            'analysis_id': analysis_id,
            'error': str(e)
        }, room=analysis_id)


# =============================================================================
# REST Endpoints (alongside WebSocket)
# =============================================================================

@app.route('/')
def index():
    """API info endpoint."""
    return jsonify({
        'service': 'MIESC WebSocket API',
        'version': MIESC_VERSION,
        'websocket_path': '/socket.io/',
        'status': 'operational',
        'active_analyses': len(active_analyses),
        'connected_clients': len(connected_clients),
        'endpoints': {
            'ws': {
                'connect': 'Connect to WebSocket',
                'start_analysis': 'Start contract analysis',
                'join_analysis': 'Subscribe to analysis updates',
                'get_analysis_status': 'Get analysis status',
                'cancel_analysis': 'Cancel running analysis'
            },
            'rest': {
                'GET /': 'API info',
                'GET /health': 'Health check',
                'GET /analyses': 'List active analyses'
            }
        }
    })


@app.route('/health')
def health():
    """Health check endpoint."""
    checker = HealthChecker()
    health = checker.check_all()

    return jsonify({
        'status': 'healthy' if health.status.value == 'healthy' else 'degraded',
        'websocket': 'operational',
        'tools': {
            'healthy': len(health.healthy_tools),
            'unhealthy': len(health.unhealthy_tools)
        },
        'timestamp': datetime.now().isoformat()
    })


@app.route('/analyses')
def list_analyses():
    """List active analyses."""
    return jsonify({
        'analyses': list(active_analyses.values()),
        'count': len(active_analyses)
    })


@app.route('/analyses/<analysis_id>')
def get_analysis(analysis_id: str):
    """Get specific analysis details."""
    if analysis_id in active_analyses:
        return jsonify(active_analyses[analysis_id])
    return jsonify({'error': 'Analysis not found'}), 404


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Run the WebSocket server."""
    port = int(os.environ.get('MIESC_WS_PORT', 5002))
    debug = os.environ.get('MIESC_DEBUG', 'false').lower() == 'true'

    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║          MIESC WebSocket API v{MIESC_VERSION}                      ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  WebSocket: ws://localhost:{port}/socket.io/                  ║
    ║  REST API:  http://localhost:{port}/                          ║
    ║  Health:    http://localhost:{port}/health                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    socketio.run(app, host='0.0.0.0', port=port, debug=debug)


if __name__ == '__main__':
    main()
