"""
MIESC Feedback Loop System
Sistema de mejora continua basado en feedback de usuarios y métricas.
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)


class FeedbackType(Enum):
    """Tipos de feedback."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    SEVERITY_CORRECT = "severity_correct"
    SEVERITY_TOO_HIGH = "severity_too_high"
    SEVERITY_TOO_LOW = "severity_too_low"
    HELPFUL = "helpful"
    NOT_HELPFUL = "not_helpful"


@dataclass
class UserFeedback:
    """Feedback de usuario sobre un hallazgo."""
    finding_id: str
    feedback_type: FeedbackType
    timestamp: datetime
    user_id: str = "anonymous"
    notes: str = ""
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'feedback_type': self.feedback_type.value,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'notes': self.notes,
            'context': self.context,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserFeedback':
        return cls(
            finding_id=data['finding_id'],
            feedback_type=FeedbackType(data['feedback_type']),
            timestamp=datetime.fromisoformat(data['timestamp']),
            user_id=data.get('user_id', 'anonymous'),
            notes=data.get('notes', ''),
            context=data.get('context', {}),
        )


@dataclass
class ToolPerformanceMetrics:
    """Métricas de rendimiento por herramienta."""
    tool_name: str
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    severity_accuracy: float = 0.0
    avg_confidence: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    last_updated: Optional[datetime] = None

    def update_metrics(self) -> None:
        """Actualiza métricas calculadas."""
        total = self.true_positives + self.false_positives
        if total > 0:
            self.precision = self.true_positives / total
        else:
            self.precision = 0.0

        # F1 score (asumiendo recall = precision por simplicidad sin ground truth completo)
        if self.precision > 0:
            self.f1_score = 2 * (self.precision * self.precision) / (self.precision + self.precision)
        else:
            self.f1_score = 0.0

        self.last_updated = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'tool_name': self.tool_name,
            'total_findings': self.total_findings,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'severity_accuracy': round(self.severity_accuracy, 3),
            'avg_confidence': round(self.avg_confidence, 3),
            'precision': round(self.precision, 3),
            'f1_score': round(self.f1_score, 3),
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
        }


@dataclass
class VulnerabilityTypeStats:
    """Estadísticas por tipo de vulnerabilidad."""
    vuln_type: str
    occurrences: int = 0
    confirmed: int = 0
    disputed: int = 0
    avg_severity_score: float = 0.0
    common_files: List[str] = field(default_factory=list)
    common_functions: List[str] = field(default_factory=list)
    detection_tools: Dict[str, int] = field(default_factory=dict)


class FeedbackStore:
    """Almacén persistente de feedback."""

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = Path(storage_path or os.path.expanduser("~/.miesc/feedback"))
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._feedback_file = self.storage_path / "feedback_history.json"
        self._metrics_file = self.storage_path / "tool_metrics.json"
        self._stats_file = self.storage_path / "vuln_stats.json"

    def save_feedback(self, feedback: UserFeedback) -> None:
        """Guarda feedback individual."""
        history = self._load_feedback_history()
        history.append(feedback.to_dict())
        self._save_json(self._feedback_file, history)

    def get_feedback_history(
        self,
        days: int = 30,
        feedback_type: Optional[FeedbackType] = None,
    ) -> List[UserFeedback]:
        """Obtiene historial de feedback."""
        history = self._load_feedback_history()
        cutoff = datetime.now() - timedelta(days=days)

        result = []
        for entry in history:
            fb = UserFeedback.from_dict(entry)
            if fb.timestamp >= cutoff:
                if feedback_type is None or fb.feedback_type == feedback_type:
                    result.append(fb)

        return result

    def save_tool_metrics(self, metrics: Dict[str, ToolPerformanceMetrics]) -> None:
        """Guarda métricas de herramientas."""
        data = {name: m.to_dict() for name, m in metrics.items()}
        self._save_json(self._metrics_file, data)

    def load_tool_metrics(self) -> Dict[str, ToolPerformanceMetrics]:
        """Carga métricas de herramientas."""
        if not self._metrics_file.exists():
            return {}

        data = self._load_json(self._metrics_file)
        metrics = {}
        for name, m in data.items():
            metrics[name] = ToolPerformanceMetrics(
                tool_name=m['tool_name'],
                total_findings=m.get('total_findings', 0),
                true_positives=m.get('true_positives', 0),
                false_positives=m.get('false_positives', 0),
                severity_accuracy=m.get('severity_accuracy', 0.0),
                avg_confidence=m.get('avg_confidence', 0.0),
                precision=m.get('precision', 0.0),
                f1_score=m.get('f1_score', 0.0),
                last_updated=datetime.fromisoformat(m['last_updated']) if m.get('last_updated') else None,
            )
        return metrics

    def _load_feedback_history(self) -> List[Dict[str, Any]]:
        """Carga historial de feedback."""
        if not self._feedback_file.exists():
            return []
        return self._load_json(self._feedback_file)

    def _save_json(self, path: Path, data: Any) -> None:
        """Guarda JSON a disco."""
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def _load_json(self, path: Path) -> Any:
        """Carga JSON de disco."""
        with open(path) as f:
            return json.load(f)


class ModelRetrainer:
    """Componente para reentrenar modelos basado en feedback."""

    def __init__(self, min_samples: int = 50):
        self.min_samples = min_samples
        self._training_queue: List[Dict[str, Any]] = []
        self._last_retrain: Optional[datetime] = None

    def queue_training_sample(
        self,
        finding: Dict[str, Any],
        feedback: UserFeedback,
    ) -> None:
        """Añade muestra a cola de entrenamiento."""
        sample = {
            'finding': finding,
            'label': feedback.feedback_type.value,
            'timestamp': feedback.timestamp.isoformat(),
        }
        self._training_queue.append(sample)

    def should_retrain(self) -> bool:
        """Verifica si hay suficientes muestras para reentrenar."""
        if len(self._training_queue) < self.min_samples:
            return False

        # Evitar reentrenamiento frecuente
        if self._last_retrain:
            hours_since = (datetime.now() - self._last_retrain).total_seconds() / 3600
            if hours_since < 24:
                return False

        return True

    def get_training_data(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Obtiene datos de entrenamiento."""
        features = []
        labels = []

        for sample in self._training_queue:
            features.append(sample['finding'])
            labels.append(sample['label'])

        return features, labels

    def mark_retrained(self) -> None:
        """Marca que se realizó reentrenamiento."""
        self._last_retrain = datetime.now()
        self._training_queue = []  # Limpiar cola


class FeedbackLoop:
    """
    Sistema principal de feedback loop para mejora continua.

    Características:
    1. Recolección de feedback de usuarios
    2. Tracking de métricas por herramienta
    3. Ajuste automático de pesos/confianza
    4. Detección de patrones de falsos positivos
    5. Señales para reentrenamiento de modelos
    """

    def __init__(
        self,
        storage_path: Optional[str] = None,
        auto_adjust: bool = True,
    ):
        self.store = FeedbackStore(storage_path)
        self.retrainer = ModelRetrainer()
        self.auto_adjust = auto_adjust

        self._tool_metrics: Dict[str, ToolPerformanceMetrics] = {}
        self._vuln_stats: Dict[str, VulnerabilityTypeStats] = {}
        self._confidence_adjustments: Dict[str, float] = {}
        self._callbacks: List[Callable[[UserFeedback], None]] = []

        self._load_state()

    def _load_state(self) -> None:
        """Carga estado persistido."""
        self._tool_metrics = self.store.load_tool_metrics()

    def register_callback(self, callback: Callable[[UserFeedback], None]) -> None:
        """Registra callback para procesar feedback."""
        self._callbacks.append(callback)

    def submit_feedback(
        self,
        finding: Dict[str, Any],
        feedback_type: FeedbackType,
        user_id: str = "anonymous",
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Registra feedback de usuario sobre un hallazgo.

        Args:
            finding: Hallazgo original
            feedback_type: Tipo de feedback
            user_id: ID del usuario
            notes: Notas adicionales

        Returns:
            Dict con resultado del procesamiento
        """
        # Generar ID único para el hallazgo
        finding_id = self._compute_finding_id(finding)

        feedback = UserFeedback(
            finding_id=finding_id,
            feedback_type=feedback_type,
            timestamp=datetime.now(),
            user_id=user_id,
            notes=notes,
            context={
                'tool': finding.get('tool', 'unknown'),
                'type': finding.get('type', ''),
                'severity': finding.get('severity', ''),
                'location': finding.get('location', {}),
            },
        )

        # Persistir feedback
        self.store.save_feedback(feedback)

        # Actualizar métricas
        self._update_metrics(finding, feedback)

        # Añadir a cola de entrenamiento
        self.retrainer.queue_training_sample(finding, feedback)

        # Ejecutar callbacks
        for callback in self._callbacks:
            try:
                callback(feedback)
            except Exception as e:
                logger.warning(f"Feedback callback error: {e}")

        # Auto-ajustar si está habilitado
        if self.auto_adjust:
            self._auto_adjust_confidence(finding, feedback)

        return {
            'status': 'success',
            'finding_id': finding_id,
            'feedback_type': feedback_type.value,
            'metrics_updated': True,
            'retrain_recommended': self.retrainer.should_retrain(),
        }

    def _compute_finding_id(self, finding: Dict[str, Any]) -> str:
        """Genera ID único para un hallazgo."""
        parts = [
            finding.get('tool', ''),
            finding.get('type', ''),
            str(finding.get('location', {}).get('file', '')),
            str(finding.get('location', {}).get('line', 0)),
            finding.get('message', '')[:100],
        ]
        return hashlib.sha256('|'.join(parts).encode()).hexdigest()[:16]

    def _update_metrics(self, finding: Dict[str, Any], feedback: UserFeedback) -> None:
        """Actualiza métricas basadas en feedback."""
        tool = finding.get('tool', 'unknown')
        vuln_type = finding.get('type', 'unknown')

        # Métricas por herramienta
        if tool not in self._tool_metrics:
            self._tool_metrics[tool] = ToolPerformanceMetrics(tool_name=tool)

        metrics = self._tool_metrics[tool]
        metrics.total_findings += 1

        if feedback.feedback_type == FeedbackType.TRUE_POSITIVE:
            metrics.true_positives += 1
        elif feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
            metrics.false_positives += 1
        elif feedback.feedback_type == FeedbackType.SEVERITY_CORRECT:
            # Incrementar accuracy de severidad
            total = metrics.true_positives + metrics.false_positives
            if total > 0:
                metrics.severity_accuracy = (
                    metrics.severity_accuracy * (total - 1) + 1.0
                ) / total
        elif feedback.feedback_type in [FeedbackType.SEVERITY_TOO_HIGH, FeedbackType.SEVERITY_TOO_LOW]:
            # Decrementar accuracy de severidad
            total = metrics.true_positives + metrics.false_positives
            if total > 0:
                metrics.severity_accuracy = (
                    metrics.severity_accuracy * (total - 1) + 0.0
                ) / total

        metrics.update_metrics()

        # Estadísticas por tipo de vulnerabilidad
        if vuln_type not in self._vuln_stats:
            self._vuln_stats[vuln_type] = VulnerabilityTypeStats(vuln_type=vuln_type)

        stats = self._vuln_stats[vuln_type]
        stats.occurrences += 1

        if feedback.feedback_type == FeedbackType.TRUE_POSITIVE:
            stats.confirmed += 1
        elif feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
            stats.disputed += 1

        # Track herramientas que detectan este tipo
        if tool not in stats.detection_tools:
            stats.detection_tools[tool] = 0
        stats.detection_tools[tool] += 1

        # Persistir métricas
        self.store.save_tool_metrics(self._tool_metrics)

    def _auto_adjust_confidence(
        self,
        finding: Dict[str, Any],
        feedback: UserFeedback,
    ) -> None:
        """Ajusta automáticamente confianza basada en feedback."""
        tool = finding.get('tool', 'unknown')
        vuln_type = finding.get('type', 'unknown')
        key = f"{tool}:{vuln_type}"

        if key not in self._confidence_adjustments:
            self._confidence_adjustments[key] = 0.0

        if feedback.feedback_type == FeedbackType.TRUE_POSITIVE:
            self._confidence_adjustments[key] = min(
                self._confidence_adjustments[key] + 0.02, 0.2
            )
        elif feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
            self._confidence_adjustments[key] = max(
                self._confidence_adjustments[key] - 0.05, -0.3
            )

    def get_confidence_adjustment(self, tool: str, vuln_type: str) -> float:
        """Obtiene ajuste de confianza para combinación tool/tipo."""
        key = f"{tool}:{vuln_type}"
        return self._confidence_adjustments.get(key, 0.0)

    def adjust_finding_confidence(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Ajusta confianza de un hallazgo basado en feedback histórico."""
        tool = finding.get('tool', 'unknown')
        vuln_type = finding.get('type', 'unknown')

        adjustment = self.get_confidence_adjustment(tool, vuln_type)
        original_confidence = finding.get('confidence', 0.7)
        new_confidence = max(0.1, min(0.95, original_confidence + adjustment))

        adjusted = finding.copy()
        adjusted['confidence'] = round(new_confidence, 3)
        adjusted['_confidence_adjusted'] = True
        adjusted['_adjustment'] = round(adjustment, 3)

        return adjusted

    def get_tool_performance(self, tool: str) -> Optional[ToolPerformanceMetrics]:
        """Obtiene métricas de rendimiento de una herramienta."""
        return self._tool_metrics.get(tool)

    def get_all_tool_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Obtiene métricas de todas las herramientas."""
        return {name: m.to_dict() for name, m in self._tool_metrics.items()}

    def get_vulnerability_insights(self) -> Dict[str, Any]:
        """Obtiene insights sobre tipos de vulnerabilidad."""
        insights = {
            'most_common': [],
            'most_disputed': [],
            'tool_specializations': {},
        }

        # Tipos más comunes
        sorted_by_occurrence = sorted(
            self._vuln_stats.values(),
            key=lambda x: x.occurrences,
            reverse=True,
        )
        insights['most_common'] = [
            {'type': s.vuln_type, 'count': s.occurrences}
            for s in sorted_by_occurrence[:10]
        ]

        # Tipos más disputados (alto ratio FP)
        for stats in self._vuln_stats.values():
            total = stats.confirmed + stats.disputed
            if total >= 5:  # Mínimo de muestras
                dispute_rate = stats.disputed / total
                if dispute_rate > 0.3:
                    insights['most_disputed'].append({
                        'type': stats.vuln_type,
                        'dispute_rate': round(dispute_rate, 2),
                        'total': total,
                    })

        insights['most_disputed'].sort(key=lambda x: -x['dispute_rate'])

        # Especialización de herramientas
        for stats in self._vuln_stats.values():
            if stats.detection_tools:
                best_tool = max(stats.detection_tools.items(), key=lambda x: x[1])
                if best_tool[0] not in insights['tool_specializations']:
                    insights['tool_specializations'][best_tool[0]] = []
                insights['tool_specializations'][best_tool[0]].append(stats.vuln_type)

        return insights

    def get_recommendations(self) -> List[Dict[str, Any]]:
        """Genera recomendaciones basadas en feedback acumulado."""
        recommendations = []

        # Recomendar desactivar herramientas con baja precisión
        for name, metrics in self._tool_metrics.items():
            if metrics.precision < 0.3 and metrics.total_findings >= 20:
                recommendations.append({
                    'type': 'tool_performance',
                    'severity': 'warning',
                    'tool': name,
                    'message': f"Tool '{name}' has low precision ({metrics.precision:.1%}). Consider reducing weight or reviewing configuration.",
                    'action': 'reduce_weight',
                })

        # Recomendar reentrenamiento
        if self.retrainer.should_retrain():
            recommendations.append({
                'type': 'retrain',
                'severity': 'info',
                'message': f"Sufficient feedback collected ({len(self.retrainer._training_queue)} samples). Consider retraining ML models.",
                'action': 'retrain_models',
            })

        # Tipos de vulnerabilidad problemáticos
        for stats in self._vuln_stats.values():
            total = stats.confirmed + stats.disputed
            if total >= 10:
                dispute_rate = stats.disputed / total
                if dispute_rate > 0.5:
                    recommendations.append({
                        'type': 'vuln_type',
                        'severity': 'warning',
                        'vuln_type': stats.vuln_type,
                        'message': f"Vulnerability type '{stats.vuln_type}' has high false positive rate ({dispute_rate:.1%}).",
                        'action': 'add_to_fp_filter',
                    })

        return recommendations

    def export_training_data(self, output_path: str) -> int:
        """Exporta datos para entrenamiento externo."""
        features, labels = self.retrainer.get_training_data()

        data = {
            'samples': [
                {'features': f, 'label': l}
                for f, l in zip(features, labels)
            ],
            'exported_at': datetime.now().isoformat(),
            'total_samples': len(features),
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        return len(features)

    def generate_report(self) -> Dict[str, Any]:
        """Genera reporte completo del sistema de feedback."""
        feedback_history = self.store.get_feedback_history(days=30)

        # Contar tipos de feedback
        feedback_counts = defaultdict(int)
        for fb in feedback_history:
            feedback_counts[fb.feedback_type.value] += 1

        return {
            'summary': {
                'total_feedback_30d': len(feedback_history),
                'feedback_by_type': dict(feedback_counts),
                'tools_tracked': len(self._tool_metrics),
                'vuln_types_tracked': len(self._vuln_stats),
            },
            'tool_metrics': self.get_all_tool_metrics(),
            'insights': self.get_vulnerability_insights(),
            'recommendations': self.get_recommendations(),
            'retrain_status': {
                'samples_queued': len(self.retrainer._training_queue),
                'min_samples': self.retrainer.min_samples,
                'should_retrain': self.retrainer.should_retrain(),
            },
            'generated_at': datetime.now().isoformat(),
        }
