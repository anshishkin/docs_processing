import time
from typing import Union

import requests
import os
from db_classification_tools import compute_sha256


logger = get_module_logger(__name__)


class HybridAnalysisHandler:

    def __init__(self, api_key: str):
        """
        Initialize the HybridAnalysisHandler.

        :param api_key: The Hybrid Analysis API key for authentication.
        """
        self.api_key = api_key
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox"
        }
        try:
            response = requests.get(f"{self.base_url}/key/current", headers=self.headers)
            response.raise_for_status()
            logger.info("Hybrid Analysis client initialized successfully")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error initializing Hybrid Analysis client: {e}")
            raise

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
            logger.info(f"Checking Hybrid Analysis for existing analysis of {sha256_hash}")
            response = requests.post(
                f"{self.base_url}/search/hash",
                headers=self.headers,
                data={"hash": sha256_hash}
            )
            response.raise_for_status()
            results = response.json()

            if results:
                verdict = results[0].get('verdict')
                is_malicious = verdict in ['malicious', 'suspicious']
                logger.info(
                    f"Analysis result for {file_path}: {'Potentially malicious' if is_malicious else 'Not malicious'}")
                return is_malicious
            else:
                logger.info(f"No existing analysis found for {file_path}. Initiating new scan.")
                return self._scan_file(file_path)

        except requests.exceptions.RequestException as e:
            logger.error(f"Hybrid Analysis API error occurred while analyzing {file_path}: {e}")
            raise

        except Exception as e:
            logger.exception(f"Unexpected error occurred while analyzing {file_path}: {e}")
            return None

    def _scan_file(self, file_path: str) -> Union[bool, None]:
        logger.info(f"Initiating new scan for file: {file_path}")

        try:
            with open(file_path, "rb") as file:
                files = {"file": file}
                data = {"environment_id": 160}  # Using Windows 10 64 bit as an example
                response = requests.post(
                    f"{self.base_url}/submit/file",
                    headers=self.headers,
                    files=files,
                    data=data
                )
            response.raise_for_status()
            result = response.json()
            job_id = result.get('job_id')
            logger.debug(f"Scan initiated for {file_path}. Job ID: {job_id}")

            start_time = time.time()
            while True:
                response = requests.get(
                    f"{self.base_url}/report/{job_id}/summary",
                    headers=self.headers
                )
                response.raise_for_status()
                status = response.json().get('status')

                if status == "finished":
                    logger.info(f"Scan completed for {file_path}. Job ID: {job_id}")
                    break
                elif time.time() - start_time > 300:  # 5 minutes timeout
                    logger.warning(f"Scan timed out for {file_path}. Job ID: {job_id}")
                    return None
                time.sleep(10)  # Wait for 10 seconds before checking again

            verdict = response.json().get('verdict')
            is_malicious = verdict in ['malicious', 'suspicious']
            logger.info(f"Scan result for {file_path}: {'Potentially malicious' if is_malicious else 'Not malicious'}")
            logger.debug(f"Detailed scan results for {file_path}: {response.json()}")
            return is_malicious

        except Exception as e:
            logger.exception(f"An error occurred while scanning {file_path}: {e}")
            return None

    def __del__(self):
        logger.info("Closing Hybrid Analysis client")
        logger.debug("Hybrid Analysis client closed successfully")
