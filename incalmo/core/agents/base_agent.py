from incalmo.core.services import EnvironmentStateService

class BaseAgent:
    """
    Parent class for all agents.

    Every agent needs:
    - access to the environment state service (read/write network state)
    - a run() method (execute the concrete task)
    - to return results in a standard format

    The 5 agents all inherit from this class:
    ScanAgent, LateralMoveAgent, FindInfoAgent,
    EscalateAgent, ExfiltrateAgent
    """

    def __init__(self, env_service: EnvironmentStateService):
        """
        env_service: the environment state service instance.
        All agents share the same environment state service,
        so when one agent updates the state, the others see it immediately.
        """
        self.env_service = env_service

    def run(self, **kwargs) -> dict:
        """
        Main method that executes the task; subclasses must override it.

        Standard return format:
        {
            "success": True/False,
            "message": "what happened",
            "data": {...}  # the actual returned data
        }
        """
        raise NotImplementedError("Subclasses must implement run()")

    def _success(self, message: str, data: dict = {}) -> dict:
        """Shortcut for returning a success result."""
        return {
            "success": True,
            "message": message,
            "data": data
        }

    def _failure(self, message: str, data: dict = {}) -> dict:
        """Shortcut for returning a failure result."""
        return {
            "success": False,
            "message": message,
            "data": data
        }
