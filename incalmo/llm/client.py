from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage

_PRICE = {
    "gpt-4o":      {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output":  0.60},
}
_DEFAULT_PRICE = {"input": 2.50, "output": 10.00}

PORTKEY_BASE_URL = "https://api.portkey.ai/v1"


class IncalmoLLMClient:
    """
    Thin wrapper around LangChain's ChatOpenAI routed through Portkey.
    Model name should be prefixed with @openai/ (e.g. "@openai/gpt-4o").
    """

    def __init__(self, model: str = "@openai/gpt-4o", api_key: str = "",
                max_tokens: int = 4096):
        self.model = model
        self._llm = ChatOpenAI(
            model=model,
            api_key=api_key or "dummy",
            base_url=PORTKEY_BASE_URL,
            max_tokens=max_tokens,
        )
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0

    def invoke(self, messages: list[dict]) -> str:
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
        bare_model = self.model.lstrip("@openai/")
        price = _PRICE.get(bare_model, _DEFAULT_PRICE)
        self.total_cost_usd += (inp * price["input"] + out * price["output"]) / 1_000_000
