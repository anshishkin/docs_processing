import time
from typing import Union

import vt
import os
from db_classification_tools import compute_sha256

class VirusTotalHandler:
    """
    Handler for interacting with the VirusTotal API.

    This class provides a streamlined interface for analyzing files for potential
    malicious content using the VirusTotal service.

    Usage of this class requires a valid VirusTotal API key.

    Methods:
        analyze_if_malicious: Determines if a given file is potentially malicious.
    """
    def __init__(self, api_key: str):
        """
        Initialize the VirusTotalHandler.

        :param api_key: The VirusTotal API key for authentication.
        """
        try:
            self.client = vt.Client(api_key)
            logger.info("VirusTotal client initialized successfully")
        except ValueError as e:
            logger.error(f"Invalid API key format: {e}")
        except ConnectionError as e:
            logger.error(f"Network connection error while initializing VirusTotal client: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error occurred while initializing VirusTotal client: {e}")

    def analyze_if_malicious(self, file_path: str) -> Union[bool, None]:
        """
        Analyze a file to determine if it's potentially malicious.

        :param file_path: Path to the file to be analyzed.
        :return: True if the file is potentially malicious, False if it's not, None if analysis couldn't be completed.
        """
        logger.info(f"Starting analysis for file: {file_path}")

        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            raise FileNotFoundError(f"The file {file_path} does not exist.")

        # Compute SHA256 hash
        try:
            sha256_hash = compute_sha256(file_path)
            logger.debug(f"Computed SHA256 hash for {file_path}: {sha256_hash}")
        except Exception as e:
            logger.error(f"Failed to compute SHA256 hash for {file_path}: {e}")
            return None

        try:
            # Check if the file has been analyzed before
            logger.info(f"Checking VirusTotal for existing analysis of {sha256_hash}")
            file_report = self.client.get_object(f"/files/{sha256_hash}")
            last_analysis_results = file_report.last_analysis_results

            is_malicious = any(
                result['category'] in ['malicious', 'suspicious'] for result in last_analysis_results.values())
            logger.info(
                f"Analysis result for {file_path}: {'Potentially malicious' if is_malicious else 'Not malicious'}")
            return is_malicious

        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                logger.info(f"No existing analysis found for {file_path}. Initiating new scan.")
                return self._scan_file(file_path)
            else:
                logger.error(f"VirusTotal API error occurred while analyzing {file_path}: {e}")
                raise

        except Exception as e:
            logger.exception(f"Unexpected error occurred while analyzing {file_path}: {e}")
            return None

    def _scan_file(self, file_path: str) -> Union[bool, None]:
        logger.info(f"Initiating new scan for file: {file_path}")

        try:
            with open(file_path, "rb") as file:
                analysis = self.client.scan_file(file)
            logger.debug(f"Scan initiated for {file_path}. Analysis ID: {analysis.id}")

            start_time = time.time()
            while True:
                analysis = self.client.get_object("/analyses/{}", analysis.id)
                if analysis.status == "completed":
                    logger.info(f"Scan completed for {file_path}. Analysis ID: {analysis.id}")
                    break
                elif time.time() - start_time > 300:  # 5 minutes timeout
                    logger.warning(f"Scan timed out for {file_path}. Analysis ID: {analysis.id}")
                    return None
                time.sleep(10)  # Wait for 10 seconds before checking again

            results = analysis.stats
            is_malicious = results.get("malicious", 0) > 0 or results.get("suspicious", 0) > 0
            logger.info(f"Scan result for {file_path}: {'Potentially malicious' if is_malicious else 'Not malicious'}")
            logger.debug(f"Detailed scan results for {file_path}: {results}")
            return is_malicious

        except Exception as e:
            logger.exception(f"An error occurred while scanning {file_path}: {e}")
            return None

    def __del__(self):
        logger.info("Closing VirusTotal client")
        try:
            self.client.close()
            logger.debug("VirusTotal client closed successfully")
        except Exception as e:
            logger.error(f"Error occurred while closing VirusTotal client: {e}")