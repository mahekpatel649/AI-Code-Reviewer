"""Interactive AI Code Assistant for querying specific findings and secure refactoring."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from ai.prompts import ASSISTANT_SYSTEM_PROMPT


PRESET_PROMPTS = [
    "Why is this code problematic?",
    "How do I fix this issue step-by-step?",
    "What are the potential security impacts if exploited?",
    "Show me alternative secure implementations in Python.",
]


class CodeAssistantEngine:
    """Provides conversational advice and explanations for identified vulnerabilities."""

    def __init__(self):
        self.api_key = os.getenv("AI_API_KEY", "").strip()
        self.model = os.getenv("AI_MODEL", "gpt-4o-mini").strip()
        self.base_url = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").strip()
        self._client = None

        if self.api_key:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url if self.base_url else None,
                    timeout=20.0,
                    max_retries=1,
                )
            except Exception:
                self._client = None

    def ask(
        self,
        finding: Dict[str, Any],
        user_question: str,
        chat_history: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        """Answer a user question regarding a specific finding."""
        if not finding:
            return "Please select a vulnerability finding from the list first to ask questions about it."

        # If live AI is available, ask LLM
        if self.api_key and self._client is not None:
            context = (
                f"FINDING DETAILS:\n"
                f"- Rule ID: {finding.get('rule_id')}\n"
                f"- Title: {finding.get('title')}\n"
                f"- Severity: {finding.get('severity')}\n"
                f"- Category: {finding.get('category')}\n"
                f"- File: {finding.get('file')}:{finding.get('line')}\n"
                f"- Description: {finding.get('description')}\n\n"
                f"CODE SNIPPET:\n```python\n{finding.get('code_snippet', '')}\n```\n\n"
                f"EXISTING AI FIX:\n```python\n{finding.get('suggested_fix', '')}\n```\n"
            )

            messages = [{"role": "system", "content": ASSISTANT_SYSTEM_PROMPT}]
            messages.append({"role": "system", "content": context})

            if chat_history:
                for msg in chat_history[-6:]:  # Keep recent history
                    messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})

            messages.append({"role": "user", "content": user_question})

            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0.3,
                )
                answer = response.choices[0].message.content
                if answer:
                    return answer.strip()
            except Exception as e:
                # Fall back to intelligent local answer
                pass

        # Intelligent offline assistant response
        q_lower = user_question.lower()
        title = finding.get("title", "this issue")
        fix = finding.get("suggested_fix", "# Refactor to use safe abstractions")
        impact = finding.get("impact", "Unauthorized access or system instability.")
        root_cause = finding.get("root_cause", "Insecure coding construct.")
        explanation = finding.get("explanation", "The flagged code pattern poses security risks.")

        if "why" in q_lower or "problematic" in q_lower or "reason" in q_lower:
            return (
                f"### Why This Code Is Problematic\n\n"
                f"**Issue:** {title}\n\n"
                f"{explanation}\n\n"
                f"**Root Cause:** {root_cause}\n\n"
                f"In production software, this pattern breaks security boundaries by trusting inputs or exposing internal application state."
            )
        elif "fix" in q_lower or "how" in q_lower or "step" in q_lower:
            return (
                f"### How to Fix This Issue\n\n"
                f"Follow these recommended steps:\n"
                f"1. **Isolate the vulnerable call:** Identify the line in `{finding.get('file')}`.\n"
                f"2. **Apply secure alternative:**\n\n"
                f"```python\n{fix}\n```\n\n"
                f"3. **Verify with tests:** Ensure unit tests validate that safe inputs work while malicious payloads are rejected.\n"
                f"4. **Static validation:** Re-run the security scan to verify the rule clears."
            )
        elif "impact" in q_lower or "risk" in q_lower or "exploit" in q_lower:
            return (
                f"### Potential Security & Operational Impacts\n\n"
                f"**Severity:** {finding.get('severity')}\n\n"
                f"**Impact Summary:** {impact}\n\n"
                f"If an attacker targets this vulnerability, consequences could include confidential data leakage, privilege escalation, or unauthorized command execution."
            )
        elif "alternative" in q_lower or "pattern" in q_lower:
            return (
                f"### Alternative Secure Implementations\n\n"
                f"Consider these defense-in-depth patterns:\n\n"
                f"1. **Modern Standard Library Approach:**\n```python\n{fix}\n```\n\n"
                f"2. **Type Hints & Input Constraints:** Constrain inputs strictly with Pydantic or schema validators.\n"
                f"3. **Least Privilege:** Ensure the process running this code operates with minimal OS privileges."
            )
        else:
            return (
                f"### Code Review Insight for `{finding.get('rule_id')}`\n\n"
                f"- **Finding:** {title}\n"
                f"- **Explanation:** {explanation}\n"
                f"- **Recommended Fix:**\n```python\n{fix}\n```\n\n"
                f"- **Prevention:** {finding.get('prevention_advice', 'Conduct regular code audits.')}"
            )
