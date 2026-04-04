ML Module
=========

Machine Learning components for vulnerability detection and false positive filtering.

.. contents:: Table of Contents
   :local:
   :depth: 2

Classic Patterns
----------------

Traditional pattern-based detection with ML-enhanced confidence scoring.

.. automodule:: src.ml.classic_patterns
   :members:
   :undoc-members:
   :show-inheritance:

DeFi Patterns
-------------

DeFi-specific vulnerability patterns.

.. automodule:: src.ml.defi_patterns
   :members:
   :undoc-members:
   :show-inheritance:

False Positive Classifier
-------------------------

ML-based false positive filtering.

.. automodule:: src.ml.fp_classifier
   :members:
   :undoc-members:
   :show-inheritance:

Correlation Engine
------------------

Finding correlation and clustering.

.. automodule:: src.ml.correlation_engine
   :members:
   :undoc-members:
   :show-inheritance:

ML Pipeline
-----------

The ML module implements a processing pipeline:

1. **Pattern Detection**: Classic and DeFi patterns
2. **FP Filtering**: Remove likely false positives
3. **Correlation**: Cluster related findings
4. **Confidence Scoring**: ML-enhanced confidence

.. code-block:: python

    from src.ml import MLPipeline

    pipeline = MLPipeline()
    result = pipeline.process(findings, code_context_map)

    print(f"Filtered: {result.fp_filtered} FPs")
    print(f"Clusters: {len(result.clusters)}")

Fine-Tuning
-----------

Dataset Generator
~~~~~~~~~~~~~~~~~

Generate training data for fine-tuning LLMs.

.. automodule:: src.ml.fine_tuning.dataset_generator
   :members:
   :undoc-members:
   :show-inheritance:

Trainer
~~~~~~~

Fine-tune models on security-specific data.

.. automodule:: src.ml.fine_tuning.fine_tuning_trainer
   :members:
   :undoc-members:
   :show-inheritance:
