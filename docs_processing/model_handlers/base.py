import abc
import logging
from abc import ABC
from typing import List, Tuple

import torch
import torch.nn as nn


class BaseTransform(nn.Module):
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            x = self.transforms(x)
            return x


class ModelHandler(ABC):
    @abc.abstractmethod
    def model_infer(
        self,
        *args,
        **kwargs,
    ):
        pass


class NNModelHandler(ModelHandler):
    model_name: str

    @abc.abstractmethod
    def load_model(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def stage_infer(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def preproc(
        self,
        *args,
        **kwargs,
    ):
        pass

    @abc.abstractmethod
    def postproc(
        self,
        *args,
        **kwargs,
    ):
        pass


class SimpleNNModelHandler(NNModelHandler, ABC):
    model_name: str
    means = [0.485, 0.456, 0.406]
    stds = [0.229, 0.224, 0.225]
    net: torch.nn.Module
    size: Tuple[int, int]
    transforms_size: torch.nn.Module
    transforms_div: torch.nn.Module

    def __init__(self, weights: str, device: torch.device):
        self.device = device
        self.logger = logging.getLogger(self.model_name)
        self.load_model(weights)
        self._transforms_size = torch.jit.script(self.transforms_size(self.size)).to(self.device)
        self._transforms_div = torch.jit.script(self.transforms_div(self.means, self.stds)).to(self.device)

    def load_model(self, weights: str):
        state_dict = torch.load(weights)
        self.logger.info("Loading weights from {}... Done!".format(weights))
        self.net.load_state_dict(state_dict)
        self.net.to(self.device).eval().half()

    def model_infer(self, im_batch: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            return self.net(im_batch)

    def preproc(self, frames: List[torch.Tensor]):
        sized = []
        for img in frames:
            sized.append(self._transforms_size(img))
        return self._transforms_div(torch.stack(sized))
