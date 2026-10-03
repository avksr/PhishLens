"""
phishlens.agents.url_agent — Production-grade URL Threat Intelligence Agent.
"""

from .models.schema import RiskSignal, URLAgentInput, URLAgentOutput
from .core.redirect_tracer import (
    RedirectHop,
    RedirectTraceResult,
    RedirectTracer,
    trace_redirects_and_cloaking,
)
from .core.homograph_engine import (
    HomographEngine,
    HomographResult,
    analyze_homograph_and_brands,
    confusable_skeleton,
)
from .core.ssl_analyzer import (
    SSLAnalysisResult,
    SSLAnalyzer,
    analyze_ssl_infrastructure,
)
from .core.dom_inspector import (
    DOMAnalysisResult,
    DOMInspector,
    inspect_dom_and_favicons,
    murmur3_favicon_hash,
)
from .url_agent import URLAgent, run_url_agent

__all__ = [
    "DOMAnalysisResult",
    "DOMInspector",
    "HomographEngine",
    "HomographResult",
    "RedirectHop",
    "RedirectTraceResult",
    "RedirectTracer",
    "RiskSignal",
    "SSLAnalysisResult",
    "SSLAnalyzer",
    "URLAgent",
    "URLAgentInput",
    "URLAgentOutput",
    "analyze_homograph_and_brands",
    "analyze_ssl_infrastructure",
    "confusable_skeleton",
    "inspect_dom_and_favicons",
    "murmur3_favicon_hash",
    "run_url_agent",
    "trace_redirects_and_cloaking",
]
