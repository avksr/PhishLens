"""
phishlens.agents.url_agent.core — High-performance URL threat analysis sub-modules.
"""

from .dom_inspector import (
    DOMAnalysisResult,
    DOMInspector,
    inspect_dom_and_favicons,
    murmur3_favicon_hash,
)
from .homograph_engine import (
    HomographEngine,
    HomographResult,
    analyze_homograph_and_brands,
    confusable_skeleton,
)
from .redirect_tracer import (
    RedirectHop,
    RedirectTraceResult,
    RedirectTracer,
    trace_redirects_and_cloaking,
)
from .ssl_analyzer import (
    SSLAnalysisResult,
    SSLAnalyzer,
    analyze_ssl_infrastructure,
)

__all__ = [
    "DOMAnalysisResult",
    "DOMInspector",
    "HomographEngine",
    "HomographResult",
    "RedirectHop",
    "RedirectTraceResult",
    "RedirectTracer",
    "SSLAnalysisResult",
    "SSLAnalyzer",
    "analyze_homograph_and_brands",
    "analyze_ssl_infrastructure",
    "confusable_skeleton",
    "inspect_dom_and_favicons",
    "murmur3_favicon_hash",
    "trace_redirects_and_cloaking",
]
