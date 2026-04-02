from enum import StrEnum


class AttackCategory(StrEnum):
    PROMPT_INJECTION_RAG = "prompt_injection_rag"
    TOOL_MISUSE = "tool_misuse"
    CROSS_AGENT_INJECTION = "cross_agent_injection"
    MEMORY_POISONING = "memory_poisoning"


class Grade(StrEnum):
    PASS = "pass"
    PARTIAL_FAIL = "partial_fail"
    FAIL = "fail"
    CRITICAL_FAIL = "critical_fail"
