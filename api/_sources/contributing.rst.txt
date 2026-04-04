Contributing
============

Thank you for your interest in contributing to MIESC!

Getting Started
---------------

1. Fork the repository on GitHub
2. Clone your fork locally
3. Set up development environment:

.. code-block:: bash

    git clone https://github.com/YOUR_USERNAME/MIESC.git
    cd MIESC
    pip install -e ".[dev]"

Development Workflow
--------------------

1. Create a feature branch:

.. code-block:: bash

    git checkout -b feat/my-feature

2. Make your changes
3. Run tests:

.. code-block:: bash

    pytest tests/ -v
    ruff check src/
    mypy src/

4. Commit with conventional commits:

.. code-block:: bash

    git commit -m "feat(adapters): add new detector adapter"

5. Push and create a pull request

Commit Convention
-----------------

We use `Conventional Commits <https://www.conventionalcommits.org/>`_:

* ``feat(scope):`` New feature
* ``fix(scope):`` Bug fix
* ``docs(scope):`` Documentation
* ``refactor(scope):`` Code refactoring
* ``test(scope):`` Test changes
* ``chore(scope):`` Maintenance

Code Style
----------

* Use ``black`` for formatting (line length: 100)
* Use ``ruff`` for linting
* Add type hints to all functions
* Write docstrings (Google style)

Example:

.. code-block:: python

    def analyze_contract(
        path: str,
        timeout: int = 300,
    ) -> AnalysisResult:
        """
        Analyze a smart contract for vulnerabilities.

        Args:
            path: Path to the Solidity file
            timeout: Analysis timeout in seconds

        Returns:
            AnalysisResult with findings and metadata

        Raises:
            FileNotFoundError: If contract file doesn't exist
        """
        ...

Adding a New Adapter
--------------------

1. Create adapter file in ``src/adapters/``
2. Implement ``ToolAdapter`` protocol
3. Add to adapter registry
4. Write tests in ``tests/``
5. Document in ``docs/api/adapters.rst``

See existing adapters for examples.

Testing
-------

Run the test suite:

.. code-block:: bash

    # All tests
    pytest tests/ -v

    # With coverage
    pytest tests/ --cov=src --cov-report=html

    # Specific test file
    pytest tests/test_slither_adapter.py -v

Documentation
-------------

Build documentation locally:

.. code-block:: bash

    cd docs
    make html
    open _build/html/index.html

Questions?
----------

* Open an issue on GitHub
* Check existing issues for similar questions
