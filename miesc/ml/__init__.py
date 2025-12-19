"""
MIESC ML Module

Machine learning pipeline for intelligent vulnerability analysis.
Includes false positive filtering, severity prediction, and clustering.
"""

try:
    from src.ml.correlation_engine import CorrelationEngine
    from src.ml.false_positive_filter import FalsePositiveFilter
    from src.ml.severity_predictor import SeverityPredictor
    from src.ml.vulnerability_clusterer import VulnerabilityClusterer
    from src.ml.code_embeddings import CodeEmbeddings
    from src.ml.feedback_loop import FeedbackLoop
except ImportError:
    CorrelationEngine = None
    FalsePositiveFilter = None
    SeverityPredictor = None
    VulnerabilityClusterer = None
    CodeEmbeddings = None
    FeedbackLoop = None

__all__ = [
    "CorrelationEngine",
    "FalsePositiveFilter",
    "SeverityPredictor",
    "VulnerabilityClusterer",
    "CodeEmbeddings",
    "FeedbackLoop",
]
