"""Acuario LLM facade.

Audit pipeline talks to providers via ``AsyncLLMClient`` (native Rust-backed
client over genai-pyo3). The lightweight LangChain-shaped helpers in
``chat.py`` (``ChatModel``, ``BaseMessage``, etc.) are kept for the
``setup`` / ``doctor`` test-invokes and the runner's fallback path.
"""

from genai_pyo3 import ChatMessage, ChatResponse, ToolCall, Usage

from .chat import (
    AIMessage,
    BaseMessage,
    ChatModel,
    HumanMessage,
    SystemMessage,
    ToolMessage,
    extract_text_content,
)
from .native import (
    AsyncLLMClient,
    NativeToolSpec,
    extract_json_array,
    extract_json_object,
)

__all__ = [
    "AIMessage",
    "AsyncLLMClient",
    "BaseMessage",
    "ChatMessage",
    "ChatModel",
    "ChatResponse",
    "HumanMessage",
    "NativeToolSpec",
    "SystemMessage",
    "ToolCall",
    "ToolMessage",
    "Usage",
    "extract_json_array",
    "extract_json_object",
    "extract_text_content",
]
