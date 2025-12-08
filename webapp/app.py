#!/usr/bin/env python3
"""
MIESC v4.0.0 - Interactive Web Dashboard
Streamlit-based interface for smart contract security analysis

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
"""

import streamlit as st
import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.miesc_core import MIESCCore
from src.miesc_policy_mapper import PolicyMapper
from src.miesc_risk_engine import RiskEngine

# Licensing system
from src.licensing import LicenseManager, QuotaChecker, License

# =============================================================================
# INTERNATIONALIZATION (i18n) - English default, Spanish available
# =============================================================================

TRANSLATIONS = {
    "en": {
        # Header
        "main_title": "MIESC v4.0.0",
        "subtitle": "Multi-layer Intelligent Evaluation for Smart Contracts",

        # Sidebar
        "configuration": "Configuration",
        "security_tools": "Security Tools",
        "enable_ai": "Enable AI Correlation",
        "timeout_label": "Timeout per tool (seconds)",
        "about": "About",
        "author": "Author",
        "institution": "Institution",
        "license": "License",
        "security_adapters": "Security Adapters",
        "defense_layers": "Defense Layers",
        "precision": "Precision",
        "language": "Language",

        # Tabs
        "tab_upload": "Upload & Analyze",
        "tab_results": "Results",
        "tab_report": "Report",
        "tab_status": "System Status",
        "tab_thesis": "Thesis",

        # Upload tab
        "upload_contract": "Upload Smart Contract",
        "choose_file": "Choose a Solidity file",
        "upload_help": "Upload a .sol file for security analysis",
        "loaded": "Loaded",
        "paste_code": "Or paste code directly:",
        "solidity_code": "Solidity Code",
        "demo_contracts": "Quick Demo Contracts",
        "load": "Load",
        "contract_preview": "Contract Preview",
        "run_analysis": "Run Security Analysis",
        "analyzing": "Analyzing contract...",
        "analysis_complete": "Analysis complete! Go to Results tab.",
        "analysis_error": "Error during analysis",

        # Results tab
        "summary": "Summary",
        "total_findings": "Total Findings",
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low_info": "Low/Info",
        "detailed_findings": "Detailed Findings",
        "tool": "Tool",
        "severity": "Severity",
        "description": "Description",
        "location": "Location",
        "recommendation": "Recommendation",
        "no_vulnerabilities": "No vulnerabilities found!",
        "compliance_status": "Compliance Status",
        "compliance_score": "Compliance Score",
        "policies_checked": "Policies Checked",
        "risk_assessment": "Risk Assessment",
        "risk_level": "Risk Level",
        "upload_first": "Upload and analyze a contract first to see results here.",

        # Report tab
        "export_report": "Export Report",
        "download_json": "Download JSON Report",
        "download_md": "Download Markdown Report",
        "report_preview": "Report Preview",
        "generate_report_first": "Upload and analyze a contract first to generate a report.",

        # System status tab
        "system_status": "System Status",
        "security_tools_status": "Security Tools",
        "not_installed": "Not installed",
        "ai_llm_services": "AI/LLM Services",
        "models_available": "models available",
        "not_running": "Not running",
        "miesc_info": "MIESC Info",
        "version": "Version",
        "adapters": "Adapters",
        "layers": "Layers",
        "recall": "Recall",

        # Thesis tab
        "thesis_title": "Master's Thesis",
        "thesis_subtitle": "MIESC: Multi-layer Intelligent Evaluation for Smart Contracts",
        "thesis_author": "Author: Fernando Boiero",
        "thesis_institution": "Institution: UNDEF - IUA Cordoba",
        "thesis_year": "Year: 2024",
        "select_chapter": "Select Chapter",
        "chapter_not_found": "Chapter not found. Please check if the file exists.",
        "chapter_1": "1. Introduction",
        "chapter_2": "2. Theoretical Framework",
        "chapter_3": "3. State of the Art",
        "chapter_4": "4. Development",
        "chapter_5": "5. Experimental Results",
        "chapter_6": "6. AI and Sovereign LLM Justification",
        "chapter_7": "7. MCP Justification",
        "chapter_8": "8. Future Work",

        # Footer
        "footer": "MIESC v4.0.0 | Fernando Boiero | UNDEF - IUA Cordoba",

        # License activation
        "license_activation": "License Activation",
        "enter_license_key": "Enter your license key to access MIESC",
        "license_key_placeholder": "MIESC-XXXX-XXXX-XXXX-XXXX",
        "activate_button": "Activate License",
        "invalid_license": "Invalid or expired license key",
        "license_valid": "License activated successfully!",
        "license_info": "License Information",
        "license_plan": "Plan",
        "license_email": "Email",
        "license_expires": "Expires",
        "license_perpetual": "Perpetual",
        "usage_this_month": "Usage this month",
        "audits_remaining": "audits remaining",
        "unlimited": "Unlimited",
        "quota_exceeded": "Monthly quota exceeded. Upgrade your plan for more audits.",
        "tool_not_allowed": "Tool not available in your plan",
        "ai_not_allowed": "AI features not available in your plan",
        "logout_license": "Logout",
    },
    "es": {
        # Header
        "main_title": "MIESC v4.0.0",
        "subtitle": "Evaluacion Inteligente Multi-capa para Contratos Inteligentes",

        # Sidebar
        "configuration": "Configuracion",
        "security_tools": "Herramientas de Seguridad",
        "enable_ai": "Habilitar Correlacion IA",
        "timeout_label": "Tiempo limite por herramienta (segundos)",
        "about": "Acerca de",
        "author": "Autor",
        "institution": "Institucion",
        "license": "Licencia",
        "security_adapters": "Adaptadores de Seguridad",
        "defense_layers": "Capas de Defensa",
        "precision": "Precision",
        "language": "Idioma",

        # Tabs
        "tab_upload": "Subir y Analizar",
        "tab_results": "Resultados",
        "tab_report": "Informe",
        "tab_status": "Estado del Sistema",
        "tab_thesis": "Tesis",

        # Upload tab
        "upload_contract": "Subir Contrato Inteligente",
        "choose_file": "Elegir archivo Solidity",
        "upload_help": "Sube un archivo .sol para analisis de seguridad",
        "loaded": "Cargado",
        "paste_code": "O pegar codigo directamente:",
        "solidity_code": "Codigo Solidity",
        "demo_contracts": "Contratos de Demostracion",
        "load": "Cargar",
        "contract_preview": "Vista Previa del Contrato",
        "run_analysis": "Ejecutar Analisis de Seguridad",
        "analyzing": "Analizando contrato...",
        "analysis_complete": "Analisis completado! Ve a la pestana Resultados.",
        "analysis_error": "Error durante el analisis",

        # Results tab
        "summary": "Resumen",
        "total_findings": "Total de Hallazgos",
        "critical": "Critico",
        "high": "Alto",
        "medium": "Medio",
        "low_info": "Bajo/Info",
        "detailed_findings": "Hallazgos Detallados",
        "tool": "Herramienta",
        "severity": "Severidad",
        "description": "Descripcion",
        "location": "Ubicacion",
        "recommendation": "Recomendacion",
        "no_vulnerabilities": "No se encontraron vulnerabilidades!",
        "compliance_status": "Estado de Cumplimiento",
        "compliance_score": "Puntuacion de Cumplimiento",
        "policies_checked": "Politicas Verificadas",
        "risk_assessment": "Evaluacion de Riesgo",
        "risk_level": "Nivel de Riesgo",
        "upload_first": "Sube y analiza un contrato primero para ver resultados aqui.",

        # Report tab
        "export_report": "Exportar Informe",
        "download_json": "Descargar Informe JSON",
        "download_md": "Descargar Informe Markdown",
        "report_preview": "Vista Previa del Informe",
        "generate_report_first": "Sube y analiza un contrato primero para generar un informe.",

        # System status tab
        "system_status": "Estado del Sistema",
        "security_tools_status": "Herramientas de Seguridad",
        "not_installed": "No instalado",
        "ai_llm_services": "Servicios IA/LLM",
        "models_available": "modelos disponibles",
        "not_running": "No ejecutandose",
        "miesc_info": "Info MIESC",
        "version": "Version",
        "adapters": "Adaptadores",
        "layers": "Capas",
        "recall": "Recall",

        # Thesis tab
        "thesis_title": "Tesis de Maestria",
        "thesis_subtitle": "MIESC: Evaluacion Inteligente Multi-capa para Contratos Inteligentes",
        "thesis_author": "Autor: Fernando Boiero",
        "thesis_institution": "Institucion: UNDEF - IUA Cordoba",
        "thesis_year": "Ano: 2024",
        "select_chapter": "Seleccionar Capitulo",
        "chapter_not_found": "Capitulo no encontrado. Verifica si el archivo existe.",
        "chapter_1": "1. Introduccion",
        "chapter_2": "2. Marco Teorico",
        "chapter_3": "3. Estado del Arte",
        "chapter_4": "4. Desarrollo",
        "chapter_5": "5. Resultados Experimentales",
        "chapter_6": "6. Justificacion IA y LLM Soberano",
        "chapter_7": "7. Justificacion MCP",
        "chapter_8": "8. Trabajos Futuros",

        # Footer
        "footer": "MIESC v4.0.0 | Fernando Boiero | UNDEF - IUA Cordoba",

        # License activation
        "license_activation": "Activacion de Licencia",
        "enter_license_key": "Ingresa tu clave de licencia para acceder a MIESC",
        "license_key_placeholder": "MIESC-XXXX-XXXX-XXXX-XXXX",
        "activate_button": "Activar Licencia",
        "invalid_license": "Clave de licencia invalida o expirada",
        "license_valid": "Licencia activada exitosamente!",
        "license_info": "Informacion de Licencia",
        "license_plan": "Plan",
        "license_email": "Email",
        "license_expires": "Expira",
        "license_perpetual": "Perpetua",
        "usage_this_month": "Uso este mes",
        "audits_remaining": "auditorias restantes",
        "unlimited": "Ilimitado",
        "quota_exceeded": "Cuota mensual excedida. Actualiza tu plan para mas auditorias.",
        "tool_not_allowed": "Herramienta no disponible en tu plan",
        "ai_not_allowed": "Funciones de IA no disponibles en tu plan",
        "logout_license": "Cerrar Sesion",
    }
}

# Thesis chapter file mappings
THESIS_CHAPTERS = {
    "en": {
        "chapter_1": "docs/tesis/en/CHAPTER_INTRODUCTION.md",
        "chapter_2": "docs/tesis/en/CHAPTER_THEORETICAL_FRAMEWORK.md",
        "chapter_3": "docs/tesis/en/CHAPTER_STATE_OF_THE_ART.md",
        "chapter_4": "docs/tesis/en/CHAPTER_DEVELOPMENT.md",
        "chapter_5": "docs/tesis/en/CHAPTER_RESULTS.md",
        "chapter_6": "docs/tesis/en/CHAPTER_AI_JUSTIFICATION.md",
        "chapter_7": "docs/tesis/en/CHAPTER_MCP_JUSTIFICATION.md",
        "chapter_8": "docs/tesis/en/CHAPTER_FUTURE_WORK.md",
    },
    "es": {
        "chapter_1": "docs/tesis/CAPITULO_INTRODUCCION.md",
        "chapter_2": "docs/tesis/CAPITULO_MARCO_TEORICO.md",
        "chapter_3": "docs/tesis/CAPITULO_ESTADO_DEL_ARTE.md",
        "chapter_4": "docs/tesis/CAPITULO_DESARROLLO.md",
        "chapter_5": "docs/tesis/CAPITULO_RESULTADOS.md",
        "chapter_6": "docs/tesis/CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md",
        "chapter_7": "docs/tesis/CAPITULO_JUSTIFICACION_MCP.md",
        "chapter_8": "docs/tesis/CAPITULO_TRABAJOS_FUTUROS.md",
    }
}

def t(key: str) -> str:
    """Get translation for current language."""
    lang = st.session_state.get('language', 'en')
    return TRANSLATIONS.get(lang, TRANSLATIONS['en']).get(key, key)

def get_base_path() -> Path:
    """Get the base path of the MIESC project."""
    return Path(__file__).parent.parent

def load_chapter(chapter_key: str) -> str:
    """Load a thesis chapter file."""
    lang = st.session_state.get('language', 'en')
    chapter_path = THESIS_CHAPTERS.get(lang, {}).get(chapter_key)

    if not chapter_path:
        return t("chapter_not_found")

    full_path = get_base_path() / chapter_path

    if full_path.exists():
        return full_path.read_text(encoding='utf-8')
    else:
        return t("chapter_not_found")

# =============================================================================
# LICENSE MANAGEMENT
# =============================================================================

# Initialize license managers (cached for performance)
@st.cache_resource
def get_license_manager():
    """Get cached LicenseManager instance."""
    return LicenseManager()

@st.cache_resource
def get_quota_checker():
    """Get cached QuotaChecker instance."""
    return QuotaChecker()

def show_activation_screen():
    """Display license activation screen."""
    st.markdown(f'<p class="main-header">{t("main_title")}</p>', unsafe_allow_html=True)
    st.markdown(f'<p class="sub-header">{t("subtitle")}</p>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown(f"### {t('license_activation')}")
    st.markdown(t('enter_license_key'))

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        license_key = st.text_input(
            "License Key",
            placeholder=t('license_key_placeholder'),
            label_visibility="collapsed"
        )

        if st.button(t('activate_button'), type="primary", use_container_width=True):
            if license_key:
                manager = get_license_manager()
                license_obj = manager.validate(license_key)

                if license_obj:
                    st.session_state.license = license_obj
                    st.session_state.license_key = license_key
                    st.success(t('license_valid'))
                    st.rerun()
                else:
                    st.error(t('invalid_license'))
            else:
                st.warning(t('enter_license_key'))

def show_license_info_sidebar():
    """Display license information in sidebar."""
    license_obj = st.session_state.get('license')
    if not license_obj:
        return

    st.markdown("---")
    st.markdown(f"### {t('license_info')}")
    st.markdown(f"**{t('license_plan')}:** {license_obj.plan.value}")
    st.markdown(f"**{t('license_email')}:** {license_obj.email[:20]}...")

    if license_obj.expires_at:
        st.markdown(f"**{t('license_expires')}:** {license_obj.expires_at.strftime('%Y-%m-%d')}")
    else:
        st.markdown(f"**{t('license_expires')}:** {t('license_perpetual')}")

    # Usage info
    quota = get_quota_checker()
    remaining = quota.get_remaining_audits(license_obj)
    if remaining == -1:
        st.markdown(f"**{t('usage_this_month')}:** {t('unlimited')}")
    else:
        st.markdown(f"**{t('usage_this_month')}:** {remaining} {t('audits_remaining')}")

    # Logout button
    if st.button(t('logout_license'), use_container_width=True):
        del st.session_state.license
        del st.session_state.license_key
        st.rerun()

def get_allowed_tools_for_license(all_tools: list) -> list:
    """Filter tools based on license plan."""
    license_obj = st.session_state.get('license')
    if not license_obj:
        return []

    quota = get_quota_checker()
    return quota.filter_tools(license_obj, all_tools)

def can_use_ai_features() -> bool:
    """Check if AI features are allowed for current license."""
    license_obj = st.session_state.get('license')
    if not license_obj:
        return False

    quota = get_quota_checker()
    return quota.can_use_ai(license_obj)

def can_run_analysis() -> bool:
    """Check if user can run another analysis."""
    license_obj = st.session_state.get('license')
    if not license_obj:
        return False

    quota = get_quota_checker()
    return quota.can_analyze(license_obj)

def record_analysis():
    """Record an analysis execution."""
    license_obj = st.session_state.get('license')
    if license_obj:
        quota = get_quota_checker()
        quota.record_audit(license_obj)

# Page configuration
st.set_page_config(
    page_title="MIESC v4.0.0",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'language' not in st.session_state:
    st.session_state.language = 'en'  # English as default
if 'results' not in st.session_state:
    st.session_state.results = None
if 'contract_code' not in st.session_state:
    st.session_state.contract_code = None
if 'license' not in st.session_state:
    st.session_state.license = None
if 'license_key' not in st.session_state:
    st.session_state.license_key = None

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #667eea;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .severity-critical { color: #dc3545; font-weight: bold; }
    .severity-high { color: #fd7e14; font-weight: bold; }
    .severity-medium { color: #ffc107; }
    .severity-low { color: #17a2b8; }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .thesis-content {
        max-width: 800px;
        margin: 0 auto;
        padding: 20px;
        background: #fafafa;
        border-radius: 10px;
    }
    .lang-toggle {
        display: flex;
        justify-content: center;
        gap: 10px;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# Check license activation
if not st.session_state.license:
    show_activation_screen()
    st.stop()

# Sidebar (only shown when license is active)
with st.sidebar:
    st.image("https://img.shields.io/badge/version-4.0.0-blue", width=100)

    # Language selector at the top
    st.markdown("---")
    st.markdown(f"### {t('language')}")

    lang_col1, lang_col2 = st.columns(2)
    with lang_col1:
        if st.button("English", use_container_width=True,
                     type="primary" if st.session_state.language == 'en' else "secondary"):
            st.session_state.language = 'en'
            st.rerun()
    with lang_col2:
        if st.button("Espanol", use_container_width=True,
                     type="primary" if st.session_state.language == 'es' else "secondary"):
            st.session_state.language = 'es'
            st.rerun()

    st.markdown("---")
    st.markdown(f"### {t('configuration')}")

    # Tool selection - filtered by license plan
    all_tools = ["slither", "mythril", "aderyn", "solhint", "securify2"]
    available_tools = get_allowed_tools_for_license(all_tools)

    # Show available tools with info about restricted ones
    if len(available_tools) < len(all_tools):
        restricted = set(all_tools) - set(available_tools)
        st.caption(f"{t('tool_not_allowed')}: {', '.join(restricted)}")

    selected_tools = st.multiselect(
        t("security_tools"),
        available_tools,
        default=[available_tools[0]] if available_tools else []
    )

    # AI options - disabled if not allowed by plan
    ai_allowed = can_use_ai_features()
    if ai_allowed:
        enable_ai = st.checkbox(t("enable_ai"), value=False)
    else:
        enable_ai = st.checkbox(t("enable_ai"), value=False, disabled=True)
        st.caption(t("ai_not_allowed"))

    # Timeout
    timeout = st.slider(t("timeout_label"), 30, 300, 120)

    # License info section
    show_license_info_sidebar()

    st.markdown("---")
    st.markdown(f"### {t('about')}")
    st.markdown(f"""
    **{t('author')}:** Fernando Boiero
    **{t('institution')}:** UNDEF - IUA Cordoba
    **{t('license')}:** GPL-3.0

    **25** {t('security_adapters')}
    **7** {t('defense_layers')}
    **94.5%** {t('precision')}
    """)

# Header
st.markdown(f'<p class="main-header">{t("main_title")}</p>', unsafe_allow_html=True)
st.markdown(f'<p class="sub-header">{t("subtitle")}</p>', unsafe_allow_html=True)

# Main content with tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    f"{t('tab_upload')}",
    f"{t('tab_results')}",
    f"{t('tab_report')}",
    f"{t('tab_status')}",
    f"{t('tab_thesis')}"
])

with tab1:
    st.markdown(f"### {t('upload_contract')}")

    col1, col2 = st.columns([1, 1])

    with col1:
        uploaded_file = st.file_uploader(
            t("choose_file"),
            type=['sol'],
            help=t("upload_help")
        )

        if uploaded_file:
            st.session_state.contract_code = uploaded_file.read().decode('utf-8')
            st.success(f"{t('loaded')}: {uploaded_file.name}")

    with col2:
        st.markdown(f"**{t('paste_code')}**")
        code_input = st.text_area(
            t("solidity_code"),
            height=200,
            placeholder="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract MyContract {\n    // ...\n}"
        )
        if code_input:
            st.session_state.contract_code = code_input

    # Sample contracts
    st.markdown("---")
    st.markdown(f"### {t('demo_contracts')}")

    demo_contracts = {
        "Reentrancy Vulnerable": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;  // State updated after external call!
    }
}''',
        "Integer Overflow": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;  // Old version without SafeMath

contract TokenSale {
    mapping(address => uint256) public balances;
    uint256 public price = 1 ether;

    function buy(uint256 amount) public payable {
        // Potential overflow in older Solidity versions
        uint256 cost = amount * price;
        require(msg.value >= cost, "Not enough ETH");
        balances[msg.sender] += amount;
    }
}''',
        "Access Control Missing": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Missing access control!
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function withdraw() public {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}'''
    }

    demo_cols = st.columns(len(demo_contracts))
    for i, (name, code) in enumerate(demo_contracts.items()):
        with demo_cols[i]:
            if st.button(f"{t('load')}: {name}", key=f"demo_{i}"):
                st.session_state.contract_code = code
                st.rerun()

    # Analysis button
    st.markdown("---")
    if st.session_state.contract_code:
        st.markdown(f"### {t('contract_preview')}")
        st.code(st.session_state.contract_code[:1000] + ("..." if len(st.session_state.contract_code) > 1000 else ""), language="solidity")

        # Check quota before showing button
        can_analyze = can_run_analysis()

        if not can_analyze:
            st.error(t('quota_exceeded'))

        if st.button(f"{t('run_analysis')}", type="primary", use_container_width=True, disabled=not can_analyze):
            with st.spinner(t("analyzing")):
                try:
                    # Save to temp file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                        f.write(st.session_state.contract_code)
                        temp_path = f.name

                    # Run analysis
                    core = MIESCCore()
                    results = core.scan(temp_path, tools=selected_tools)

                    # Record usage for quota tracking
                    record_analysis()

                    # Add metadata
                    results['metadata'] = {
                        'timestamp': datetime.now().isoformat(),
                        'tools_used': selected_tools,
                        'ai_enabled': enable_ai
                    }

                    # Policy mapping
                    mapper = PolicyMapper()
                    results['compliance'] = mapper.map_to_policies(results.get('findings', []))

                    # Risk assessment
                    risk_engine = RiskEngine()
                    results['risk'] = risk_engine.assess(results.get('findings', []))

                    st.session_state.results = results
                    st.success(t("analysis_complete"))

                    # Cleanup
                    Path(temp_path).unlink(missing_ok=True)

                except Exception as e:
                    st.error(f"{t('analysis_error')}: {str(e)}")

with tab2:
    if st.session_state.results:
        results = st.session_state.results
        findings = results.get('findings', [])

        # Summary metrics
        st.markdown(f"### {t('summary')}")
        col1, col2, col3, col4, col5 = st.columns(5)

        severity_counts = results.get('summary', {})

        with col1:
            st.metric(t("total_findings"), len(findings))
        with col2:
            st.metric(t("critical"), severity_counts.get('Critical', 0), delta_color="inverse")
        with col3:
            st.metric(t("high"), severity_counts.get('High', 0), delta_color="inverse")
        with col4:
            st.metric(t("medium"), severity_counts.get('Medium', 0))
        with col5:
            st.metric(t("low_info"), severity_counts.get('Low', 0) + severity_counts.get('Info', 0))

        # Findings table
        st.markdown("---")
        st.markdown(f"### {t('detailed_findings')}")

        if findings:
            for i, finding in enumerate(findings):
                severity = finding.get('severity', 'Info')
                severity_color = {
                    'Critical': '',
                    'High': '',
                    'Medium': '',
                    'Low': '',
                    'Info': ''
                }.get(severity, '')

                with st.expander(f"{severity_color} {finding.get('title', 'Finding')} [{severity}]", expanded=(severity in ['Critical', 'High'])):
                    st.markdown(f"**{t('tool')}:** {finding.get('tool', 'Unknown')}")
                    st.markdown(f"**{t('severity')}:** {severity}")
                    st.markdown(f"**{t('description')}:** {finding.get('description', 'N/A')}")
                    if finding.get('location'):
                        st.markdown(f"**{t('location')}:** {finding.get('location')}")
                    if finding.get('recommendation'):
                        st.info(f"**{t('recommendation')}:** {finding.get('recommendation')}")
        else:
            st.success(t("no_vulnerabilities"))

        # Compliance
        st.markdown("---")
        st.markdown(f"### {t('compliance_status')}")
        compliance = results.get('compliance', {})

        if compliance:
            comp_col1, comp_col2 = st.columns(2)
            with comp_col1:
                score = compliance.get('score', 100)
                st.metric(t("compliance_score"), f"{score}/100")
            with comp_col2:
                policies = compliance.get('mapped_policies', [])
                st.metric(t("policies_checked"), len(policies))

        # Risk assessment
        st.markdown("---")
        st.markdown(f"### {t('risk_assessment')}")
        risk = results.get('risk', {})

        if risk:
            risk_score = risk.get('total_score', 0)
            risk_level = "Low" if risk_score < 30 else "Medium" if risk_score < 70 else "High"
            risk_color = "green" if risk_level == "Low" else "orange" if risk_level == "Medium" else "red"

            st.markdown(f"**{t('risk_level')}:** :{risk_color}[{risk_level}] (Score: {risk_score}/100)")

    else:
        st.info(t("upload_first"))

with tab3:
    if st.session_state.results:
        st.markdown(f"### {t('export_report')}")

        col1, col2 = st.columns(2)

        with col1:
            # JSON export
            json_report = json.dumps(st.session_state.results, indent=2, default=str)
            st.download_button(
                label=t("download_json"),
                data=json_report,
                file_name=f"miesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

        with col2:
            # Markdown export
            findings = st.session_state.results.get('findings', [])
            md_report = f"""# MIESC Security Audit Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tools Used:** {', '.join(st.session_state.results.get('metadata', {}).get('tools_used', []))}

## Summary

- **Total Findings:** {len(findings)}
- **Critical:** {st.session_state.results.get('summary', {}).get('Critical', 0)}
- **High:** {st.session_state.results.get('summary', {}).get('High', 0)}
- **Medium:** {st.session_state.results.get('summary', {}).get('Medium', 0)}
- **Low:** {st.session_state.results.get('summary', {}).get('Low', 0)}

## Findings

"""
            for f in findings:
                md_report += f"""### {f.get('title', 'Finding')}
- **Severity:** {f.get('severity', 'Info')}
- **Tool:** {f.get('tool', 'Unknown')}
- **Description:** {f.get('description', 'N/A')}

"""

            st.download_button(
                label=t("download_md"),
                data=md_report,
                file_name=f"miesc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )

        # Preview
        st.markdown("---")
        st.markdown(f"### {t('report_preview')}")
        st.json(st.session_state.results)

    else:
        st.info(t("generate_report_first"))

with tab4:
    st.markdown(f"### {t('system_status')}")

    # Check tools
    import subprocess

    tools_status = {}

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"#### {t('security_tools_status')}")

        # Slither
        try:
            result = subprocess.run(['slither', '--version'], capture_output=True, text=True, timeout=5)
            tools_status['Slither'] = ('', result.stdout.strip() or result.stderr.strip())
        except:
            tools_status['Slither'] = ('', t('not_installed'))

        # Mythril
        try:
            result = subprocess.run(['myth', 'version'], capture_output=True, text=True, timeout=5)
            tools_status['Mythril'] = ('', result.stdout.strip())
        except:
            tools_status['Mythril'] = ('', t('not_installed'))

        # Solc
        try:
            result = subprocess.run(['solc', '--version'], capture_output=True, text=True, timeout=5)
            version = result.stdout.split('\n')[1] if result.stdout else 'Unknown'
            tools_status['Solc'] = ('', version)
        except:
            tools_status['Solc'] = ('', t('not_installed'))

        for tool, (status, version) in tools_status.items():
            st.markdown(f"{status} **{tool}:** {version}")

    with col2:
        st.markdown(f"#### {t('ai_llm_services')}")

        # Ollama
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=5)
            model_count = len(result.stdout.strip().split('\n')) - 1
            st.markdown(f"**Ollama:** {model_count} {t('models_available')}")
        except:
            st.markdown(f"**Ollama:** {t('not_running')}")

        st.markdown("---")
        st.markdown(f"#### {t('miesc_info')}")
        st.markdown(f"""
        - **{t('version')}:** 4.0.0
        - **{t('adapters')}:** 25
        - **{t('layers')}:** 7
        - **{t('precision')}:** 94.5%
        - **{t('recall')}:** 92.8%
        """)

# Thesis tab
with tab5:
    st.markdown(f"### {t('thesis_title')}")
    st.markdown(f"**{t('thesis_subtitle')}**")
    st.markdown(f"_{t('thesis_author')}_")
    st.markdown(f"_{t('thesis_institution')}_")
    st.markdown(f"_{t('thesis_year')}_")

    st.markdown("---")

    # Chapter selector
    chapter_options = {
        "chapter_1": t("chapter_1"),
        "chapter_2": t("chapter_2"),
        "chapter_3": t("chapter_3"),
        "chapter_4": t("chapter_4"),
        "chapter_5": t("chapter_5"),
        "chapter_6": t("chapter_6"),
        "chapter_7": t("chapter_7"),
        "chapter_8": t("chapter_8"),
    }

    selected_chapter = st.selectbox(
        t("select_chapter"),
        options=list(chapter_options.keys()),
        format_func=lambda x: chapter_options[x]
    )

    st.markdown("---")

    # Load and display the selected chapter
    chapter_content = load_chapter(selected_chapter)
    st.markdown(chapter_content, unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown(
    f'<p style="text-align: center; color: #666;">{t("footer")}</p>',
    unsafe_allow_html=True
)
