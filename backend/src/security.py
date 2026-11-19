
import re


# Patterns that may indicate prompt injection attempts

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"disregard (all )?(previous|prior|above) instructions",
    r"reveal (the )?(system prompt|hidden instructions)",
    r"you are now (an? )?(admin|developer|system)",
    r"override (the )?(system|developer) instructions",
    r"print (all )?(passwords|secrets|credentials)",
    r"bypass (all )?(security|safety) restrictions",
    r"send .* (password|secret|credentials)",
    r"act as (an? )?(admin|developer|system)",
    r"reveal .* (system prompt|hidden instructions)",
    r"bypass .* (security|safety)",
]



# Fake protected values for testing only
PROTECTED_VALUES = [
    "TIGER-42",
    "CUST-92831",
]


def detect_injection(text):
    text_lower = text.lower()

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            return True, "Suspicious instruction detected"

    return False, "No suspicious instruction detected"


def scan_retrieved_chunks(chunks):
    safe_chunks = []
    flagged_chunks = []

    for chunk in chunks:
        detected, reason = detect_injection(chunk["text"])

        if detected:
            flagged_chunks.append({
                **chunk,
                "reason": reason
            })
        else:
            safe_chunks.append(chunk)

    return safe_chunks, flagged_chunks


def filter_sensitive_output(answer):
    filtered_answer = answer

    for secret in PROTECTED_VALUES:
        if secret.lower() in filtered_answer.lower():
            filtered_answer = re.sub(
                re.escape(secret),
                "[REDACTED]",
                filtered_answer,
                flags=re.IGNORECASE
            )

    return filtered_answer
