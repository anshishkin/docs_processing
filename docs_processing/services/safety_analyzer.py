from typing import Union

from db_classification_tools import get_module_logger
from db_classification_core.safety_analysis.av_handlers.hybrid_analysis_handler import HybridAnalysisHandler
from db_classification_core.safety_analysis.av_handlers.virustotal_handler import VirusTotalHandler


logger = get_module_logger(__name__)


class SafetyAnalyzer:
    """
    A class that combines multiple antivirus scanners to analyze files for potential malicious content.

    This class utilizes both VirusTotal and Hybrid Analysis services to provide a more comprehensive
    analysis of files.

    Usage of this class requires valid API keys for both VirusTotal and Hybrid Analysis.

    Methods:
        analyze_if_malicious: Determines if a given file is potentially malicious using multiple scanners.
    """

    def __init__(self, virustotal_api_key: str, hybrid_analysis_api_key: str):
        """
        Initialize the SafetyAnalyzer.

        :param virustotal_api_key: The VirusTotal API key for authentication.
        :param hybrid_analysis_api_key: The Hybrid Analysis API key for authentication.
        """
        try:
            self.virustotal = VirusTotalHandler(virustotal_api_key)
            self.hybrid_analysis = HybridAnalysisHandler(hybrid_analysis_api_key)
            logger.info("SafetyAnalyzer initialized successfully")
        except Exception as e:
            logger.exception(f"Error initializing SafetyAnalyzer: {e}")
            raise

    def analyze_if_malicious(self, file_path: str) -> Union[bool, None]:
        """
        Analyze a file to determine if it's potentially malicious using multiple scanners.

        :param file_path: Path to the file to be analyzed.
        :return: True if the file is potentially malicious, False if it's not, None if analysis couldn't be completed.
        """
        logger.info(f"Starting combined analysis for file: {file_path}")

        try:
            result1 = self.virustotal.analyze_if_malicious(file_path=file_path)
            result2 = self.hybrid_analysis.analyze_if_malicious(file_path=file_path)

            if result1 is not None and result2 is not None:
                is_malicious = result1 and result2
                logger.info(f"Combined analysis result for {file_path}: "
                            f"{'Potentially malicious' if is_malicious else 'Not malicious'}")
                return is_malicious
            else:
                logger.warning(f"Incomplete analysis results for {file_path}. "
                               f"VirusTotal: {result1}, Hybrid Analysis: {result2}")
                return None

        except Exception as e:
            logger.exception(f"An error occurred during combined analysis of {file_path}: {e}")
            return None

    def __del__(self):
        logger.info("Closing SafetyAnalyzer")
        try:
            del self.virustotal
            del self.hybrid_analysis
            logger.debug("SafetyAnalyzer closed successfully")
        except Exception as e:
            logger.error(f"Error occurred while closing SafetyAnalyzer: {e}")