from abc import ABC, abstractmethod


class EventCorrelator(ABC):
    @abstractmethod
    def process_event(self, event: dict) -> dict | None:
        """Process a single event and return an incident dict if one is triggered."""
        raise NotImplementedError
