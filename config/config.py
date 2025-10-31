# config.py
class ModelConfig:
    # Traditional static analysis tools
    use_slither = True
    use_mythril = False

    # AI-powered analysis
    use_rawGPT = False
    use_GPTLens = False
    use_rawLlama = False

    # Open-source AI agents
    use_ollama = False  # Local LLM (cost-free, private)
    use_crewai = False  # Multi-agent coordination

    # Ollama configuration
    ollama_model = "codellama:13b"  # Default model for Ollama

    # CrewAI configuration
    crewai_use_local_llm = True  # Use Ollama with CrewAI
    crewai_llm_model = "ollama/codellama:13b"  # Model for CrewAI agents

    # Report configuration
    include_introduction = True
    include_tools_output = True
    include_summary = False
    include_unitary_test = False
    include_conclusion = False