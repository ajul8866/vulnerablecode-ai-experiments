from agent.parsers.base import BaseParser
from agent.parsers.cwe import CWEFromSummaryParser
from agent.parsers.purl_from_cpe import PurlFromCPEParser
from agent.parsers.purl_from_summary import PurlFromSummaryParser
from agent.parsers.severity import SeverityFromSummaryParser
from agent.parsers.versions import VersionsFromSummaryParser


def test_all_existing_parsers_subclass_base():
    for klass in (
        PurlFromSummaryParser,
        PurlFromCPEParser,
        VersionsFromSummaryParser,
        SeverityFromSummaryParser,
        CWEFromSummaryParser,
    ):
        assert issubclass(klass, BaseParser)
