import enum
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


class EventTypes(enum.Enum):
    success = "success"
    unsuccess = "unsuccess"

@dataclass
class InstanceConfig:
    instance_id: str = "test"
    project: str = "docs_postprocessing"
    factory: str = "common"
    version: str = "test"
    commit: str = "test"
    virus_total_handler: bool = False
    use_hybrid_analysis: bool = True
    write_files: bool = False

@dataclass
class ModelConfig:
    llm_model_config: None

@dataclass
class AVConfig:
    vt_api_key: str = ''
    ha_api_key: str = ''
    ha_base_url = "https://www.hybrid-analysis.com/api/v2"

@dataclass
class MetricsConfig:
    port: int = 8000

@dataclass
class DocsConfig:
    network: NetworkConfig
    metrics: MetricsConfig
    model: ModelConfig
    instance: InstanceConfig
    antivir: AVConfig

