from langchain_anthropic import ChatAnthropic
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage

# Cost per 1M tokens (USD) — update if Anthropic changes pricing
_PRICE = {
    "claude-sonnet-4-6":          {"input": 3.00,  "output": 15.00},
    "claude-haiku-4-5-20251001":  {"input": 0.80,  "output":  4.00},
    "claude-opus-4-8":            {"input": 15.00, "output": 75.00},
}
_DEFAULT_PRICE = {"input": 3.00, "output": 15.00}


class IncalmoLLMClient:
    """
    Thin wrapper around LangChain's ChatAnthropic.
    Converts our plain-dict message list to LangChain objects,
    and tracks token usage + running cost across the whole session.
    """

    def __init__(self, model: str = "claude-sonnet-4-6", api_key: str = "",
                max_tokens: int = 4096):
        self.model = model
        self._llm = ChatAnthropic(
            model=model,
            api_key=api_key or None,
            max_tokens=max_tokens,
        )
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def invoke(self, messages: list[dict]) -> str:
        """
        Send a conversation to Claude and return the assistant reply as a string.

        messages: list of {"role": "system"|"user"|"assistant", "content": str}
        """
        lc_messages = self._to_langchain(messages)
        response = self._llm.invoke(lc_messages)

        self._track_usage(response)

        return response.content

    def cost_summary(self) -> str:
        return (
            f"tokens in={self.total_input_tokens:,} "
            f"out={self.total_output_tokens:,} "
            f"cost=${self.total_cost_usd:.4f}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _to_langchain(self, messages: list[dict]):
        result = []
        for m in messages:
            role = m["role"]
            content = m["content"]
            if role == "system":
                result.append(SystemMessage(content=content))
            elif role == "user":
                result.append(HumanMessage(content=content))
            elif role == "assistant":
                result.append(AIMessage(content=content))
            else:
                raise ValueError(f"Unknown role: {role}")
        return result

    def _track_usage(self, response):
        meta = getattr(response, "usage_metadata", None)
        if meta is None:
            return
        inp = meta.get("input_tokens", 0)
        out = meta.get("output_tokens", 0)
        self.total_input_tokens += inp
        self.total_output_tokens += out

        price = _PRICE.get(self.model, _DEFAULT_PRICE)
        self.total_cost_usd += (inp * price["input"] + out * price["output"]) / 1_000_000
