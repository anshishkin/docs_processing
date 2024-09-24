import sys
from typing import Union

import pandas as pd
import logging

from db_classification_llms.models import OpenAIRequester, LocalModelRequester

logger = logging.getLogger(__name__)


class CSVProcessor:
    """
    Processor for handling CSV files.

    This class provides functionality to analyze and process CSV files,
    including separator detection and dataset loading.

    Methods:
        detect_separator_statistically: Detects the CSV separator using statistical analysis.
        detect_separator_via_agent: Detects the CSV separator using an AI agent.
        get_dataset: Processes the file and returns the dataset.
        process_file: Processes the CSV file and loads it into a pandas DataFrame.
    """

    ANALYSE_X_FIRST_LINES = 10

    def __init__(
            self,
            file: str,
            process_with: Union[OpenAIRequester, LocalModelRequester],
            encoding: str = None,
            analyze_first_x_lines: int = None,
    ):
        """
        Initialize the CSVProcessor.

        :param file: Path to the CSV file.
        :param process_with: The AI model requester for separator detection.
        :param encoding: The encoding of the CSV file.
        :param analyze_first_x_lines: Number of lines to analyze for separator detection.
        """
        self.file = file
        self.encoding = encoding
        self.analyze_first_x_lines = analyze_first_x_lines or self.ANALYSE_X_FIRST_LINES
        self.llm_requester = process_with
        self.dataset = None

        logger.info(f"Initialized CSVProcessor for file: {self.file}")

    def detect_separator_statistically(self) -> str:
        """
        Detect the CSV separator using statistical analysis.

        :return: The detected separator character.
        """
        logger.info("Starting statistical separator detection")

        possible_separators = [',', '\t', ';', '|', ':', '~', '^', '||', '/', '\\', '#', '$', '&']
        separator_counts = [0] * len(possible_separators)

        try:
            with open(self.file, 'r', encoding=self.encoding) as file:
                for _ in range(self.analyze_first_x_lines):
                    line = file.readline()
                    if not line:
                        break
                    for i, separator in enumerate(possible_separators):
                        count = line.count(separator)
                        separator_counts[i] += count

            if all(count == 0 for count in separator_counts):
                logger.warning("No separators detected statistically")
                return 'fail'

            max_count_index = separator_counts.index(max(separator_counts))
            detected_separator = possible_separators[max_count_index]
            logger.info(f"Statistically detected separator: '{detected_separator}'")
            return detected_separator

        except Exception as e:
            logger.exception(f"Error during statistical separator detection: {e}")
            return 'fail'

    def detect_separator_via_agent(self) -> str:
        """
        Detect the CSV separator using an AI agent.

        :return: The detected separator character.
        """
        logger.info("Starting AI agent-based separator detection")

        try:
            with open(self.file, 'r', encoding=self.encoding) as file:
                first_x_lines = "".join(list(file)[:self.analyze_first_x_lines])

            prompt = DataSupplier().get_prompts()['determine_csv_separator'].format(self.analyze_first_x_lines)

            response = self.llm_requester.request(prompt, first_x_lines)
            detected_separator = response.strip('\'"`').replace('`', '').replace('"', '').replace("'", "")

            logger.info(f"AI agent detected separator: '{detected_separator}'")
            return detected_separator

        except Exception as e:
            logger.exception(f"Error during AI agent-based separator detection: {e}")
            return 'fail'

    def get_dataset(self) -> pd.DataFrame:
        """
        Process the file and return the dataset.

        :return: The processed pandas DataFrame.
        """
        self.process_file()
        return self.dataset

    def process_file(self) -> None:
        """
        Process the CSV file and load it into a pandas DataFrame.
        """
        logger.info(f"Starting CSV file processing for: {self.file}")

        try:
            openai_result = self.detect_separator_via_agent()
            statistical_result = self.detect_separator_statistically()

            logger.info(f"Comparing results: AI agent: '{openai_result}', Statistical: '{statistical_result}'")

            result_validity = ((openai_result == statistical_result) and
                               (len(openai_result.strip()) == len(statistical_result.strip()) == 1))

            if not result_validity:
                logger.warning(
                    f"Separator detection mismatch: AI agent: '{openai_result}', Statistical: '{statistical_result}'")
                sys.stderr.write(f"{openai_result=}\n{statistical_result=}")

            assert result_validity, "Separator detection results do not match or are invalid"

            separator = openai_result
            logger.info(f"Using detected separator: '{separator}'")

            self.dataset = pd.read_csv(self.file, delimiter=separator, encoding=self.encoding)
            logger.info(f"Successfully loaded CSV into DataFrame. Shape: {self.dataset.shape}")

        except Exception as e:
            logger.exception(f"Error occurred while processing CSV file: {e}")
            raise