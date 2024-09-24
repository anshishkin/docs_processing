import logging
import queue
import signal
import threading
import time
from functools import partial
from typing import List, Optional, Union

from docs_processing.core.config import DocsConfig, AVConfig

from docs_processing.model_handlers import (
    HybridAnalysisHandler,
    VirusTotalHandler
    )

from docs_processing.services.csv_processor import CSVProcessor
from docs_processing.services.safety_analyzer import SafetyAnalyzer

class Checker:
    hybrid_analysis_handler: HybridAnalysisHandler
    virus_total_handler: VirusTotalHandler
    csv_processor: CSVProcessor
    safety_analyzer: SafetyAnalyzer

    def __init__(self, config: DocsConfig):
        self.config = config
        self.av_config: AVConfig = self.config.antivir
        self.logger = logging.getLogger(self.__class__.__name__)
        self.start()

    def close_by_signal(self, signum, frame):
        self.exit_event.set()

    def prepare_handlers(self):

        self.hybrid_analysis_handler = HybridAnalysisHandler(
            api_key=self.av_config.ha_api_key,
            base_url=self.av_config.ha_api_key
        )
        self.virus_total_handler = VirusTotalHandler(
            api_key=self.av_config.vt_api_key
        )

    def prepare_services(self):
        if self.config.instance.write_files:
            self.logger.info("Start with file writer")

        self.csv_processor_service = CSVProcessor()

        self.safety_analyzer_serice = SafetyAnalyzer(
            hybrid_analysis_handler=self.hybrid_analysis_handler, 
            virus_total_handler = self.virus_total_handler
        )

    def prepare_app(self):
        self.prepare_handlers()
        self.prepare_services()

    def start(self):
        self.prepare_app()
    
    def stop(self):
        self.exit_event.set()

class CheckerHelper(Checker):
    def query_handler():
        pass
    def index_handler():
        pass