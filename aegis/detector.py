"""Multi-layer prompt injection & exploit detector for AegisAgent.

Combines rule-based regex heuristics, unicode normalization, base64 de-obfuscation,
and transformer-based sequence classification with token sliding-window analysis.
"""

import base64
import logging
import re
import time
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

from aegis.types import ScanResult

logger = logging.getLogger(__name__)


class InjectionDetector:
    """Enterprise-grade prompt injection and jailbreak detector."""

    DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
    CHUNK_SIZE = 450
    STRIDE = 100  # Overlap between consecutive sliding windows

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        device: Optional[str] = None,
        lazy_load: bool = False,
    ) -> None:
        """Initialize detector with compiled heuristics and Transformer classification pipeline.

        Args:
            model_name: HuggingFace model repo ID or local checkpoint path.
            device: Target torch device ('cuda', 'cpu', 'cuda:0', etc.). If None, auto-detected.
            lazy_load: If True, defer model weight loading until first inference call.
        """
        self.model_name = model_name
        if device is None:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self._pipeline = None
        self._tokenizer = None

        self._compile_heuristics()
        self._base64_regex = re.compile(
            r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        )
        self._zero_width_regex = re.compile(r"[\u200B-\u200D\uFEFF\u00A0]")

        if not lazy_load:
            self._init_model()

    def _compile_heuristics(self) -> None:
        """Compile regex heuristic patterns for immediate rule-based filtering."""
        raw_patterns = [
            ("IGNORE_INSTRUCTIONS", r"ignore\s+(all\s+)?(previous|prior)\s+instructions"),
            ("SYSTEM_OVERRIDE", r"system\s+override"),
            ("DEVELOPER_MODE", r"you\s+are\s+now\s+in\s+developer\s+mode"),
            ("BEGIN_SYSTEM_TAG", r"---BEGIN\s+SYSTEM---"),
            ("ASSISTANT_PREFIX", r"(^|\n)\s*assistant\s*:"),
            ("HTML_COMMENT_INJECTION", r"<!--[\s\S]*?(system|assistant|override|ignore|eval|exec|dump|curl|wget|admin|prompt|exfil|sqlite)[\s\S]*?-->"),
            ("SHELL_SUBCOMMAND", r"\$\([^\)]+\)"),
            ("BACKTICK_COMMAND", r"`[^`\n]+`"),
            ("PIPE_TO_SHELL", r"\|\s*(bash|sh|zsh|powershell|cmd)\b"),
            ("COMMAND_RM_RF", r"\brm\s+-(rf|fr|r|f)\b"),
            ("SQL_DROP_TABLE", r"\bDROP\s+TABLE\b"),
            ("CODE_EVAL", r"\beval\s*\("),
            ("OS_SYSTEM", r"\bos\.system\s*\("),
            ("MARKDOWN_IMAGE_EXFIL", r"!\[.*?\]\(\s*https?://[^\)]+\?[^\)]*(token|key|secret|auth|session|pass|leak|exfil|dump|q=)"),
        ]
        self.heuristic_rules: List[Tuple[str, re.Pattern]] = [
            (name, re.compile(pattern, re.IGNORECASE))
            for name, pattern in raw_patterns
        ]

    def _init_model(self) -> None:
        """Load HuggingFace model and tokenizer onto target device."""
        if self._pipeline is not None and self._tokenizer is not None:
            return

        try:
            device_id = 0 if "cuda" in self.device and torch.cuda.is_available() else -1
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            model = AutoModelForSequenceClassification.from_pretrained(self.model_name)

            self._pipeline = pipeline(
                "text-classification",
                model=model,
                tokenizer=self._tokenizer,
                device=device_id,
                truncation=False,
            )
            logger.info(
                "InjectionDetector model '%s' loaded successfully on device: %s",
                self.model_name,
                self.device,
            )
        except Exception as e:
            logger.error("Failed to load HuggingFace pipeline for '%s': %s", self.model_name, e)
            raise RuntimeError(
                f"Failed to initialize InjectionDetector model '{self.model_name}': {e}"
            ) from e

    @property
    def classification_pipeline(self) -> Any:
        """Lazy-loaded HuggingFace pipeline."""
        if self._pipeline is None:
            self._init_model()
        return self._pipeline

    @property
    def tokenizer(self) -> Any:
        """Lazy-loaded HuggingFace tokenizer."""
        if self._tokenizer is None:
            self._init_model()
        return self._tokenizer

    def normalize_text(self, text: str) -> str:
        """Normalize unicode representation and strip zero-width/invisible obfuscation characters.

        Args:
            text: Input raw string.

        Returns:
            Normalized unicode string.
        """
        if not text:
            return ""
        # Unicode normalization (NFKC compatibility decomposition + canonical composition)
        normalized = unicodedata.normalize("NFKC", text)
        # Strip zero-width / hidden spaces
        normalized = self._zero_width_regex.sub("", normalized)
        return normalized

    def _extract_and_decode_base64(self, text: str) -> List[Tuple[str, str]]:
        """Identify candidate base64 strings and decode valid UTF-8 text payloads.

        Returns:
            List of tuples: (original_matched_string, decoded_text)
        """
        matches = self._base64_regex.findall(text)
        decoded_payloads = []
        for match in matches:
            # Avoid decoding tiny false-positive alphanumeric chunks
            if len(match.strip()) < 16:
                continue
            try:
                decoded_bytes = base64.b64decode(match, validate=True)
                decoded_text = decoded_bytes.decode("utf-8")
                # Filter out pure binary / non-printable noise
                if decoded_text and any(c.isalnum() for c in decoded_text):
                    decoded_payloads.append((match, decoded_text))
            except Exception:
                continue
        return decoded_payloads

    def check_heuristics(self, text: str) -> List[str]:
        """Evaluate text against compiled regex heuristics including decoded base64 payloads.

        Args:
            text: Normalized text to inspect.

        Returns:
            List of triggered heuristic rule names.
        """
        detected = []
        # Check against direct normalized text
        for name, pattern in self.heuristic_rules:
            if pattern.search(text):
                detected.append(name)

        # Check against any embedded base64 de-obfuscated content
        base64_chunks = self._extract_and_decode_base64(text)
        for _, decoded_text in base64_chunks:
            decoded_normalized = self.normalize_text(decoded_text)
            for name, pattern in self.heuristic_rules:
                b64_rule_name = f"BASE64_OBFUSCATED_{name}"
                if pattern.search(decoded_normalized) and b64_rule_name not in detected:
                    detected.append(b64_rule_name)

        return detected

    def _chunk_text_by_tokens(self, text: str) -> List[Tuple[int, str, int]]:
        """Split text into overlapping sliding-window token segments.

        Returns:
            List of tuples: (chunk_index, chunk_text, token_count)
        """
        tokens = self.tokenizer.encode(text, add_special_tokens=False)
        total_tokens = len(tokens)

        if total_tokens <= self.CHUNK_SIZE:
            return [(0, text, total_tokens)]

        chunks = []
        step = max(1, self.CHUNK_SIZE - self.STRIDE)
        chunk_idx = 0

        for start_idx in range(0, total_tokens, step):
            end_idx = min(start_idx + self.CHUNK_SIZE, total_tokens)
            chunk_token_ids = tokens[start_idx:end_idx]
            chunk_str = self.tokenizer.decode(
                chunk_token_ids, skip_special_tokens=True, clean_up_tokenization_spaces=True
            )
            chunks.append((chunk_idx, chunk_str, len(chunk_token_ids)))
            chunk_idx += 1
            if end_idx >= total_tokens:
                break

        return chunks

    def _parse_model_output(self, prediction: List[Dict[str, Any]]) -> Tuple[float, str]:
        """Extract injection probability score and dominant label from model output.

        Returns:
            Tuple of (injection_confidence_score [0.0 to 1.0], label_name)
        """
        # HuggingFace pipeline returns e.g. [{'label': 'INJECTION', 'score': 0.99}]
        # or [{'label': 'LABEL_1', 'score': 0.99}] or [{'label': 'SAFE', 'score': 0.95}]
        top_pred = prediction[0]
        label = top_pred.get("label", "").upper()
        raw_score = float(top_pred.get("score", 0.0))

        if "INJECTION" in label or label in ("LABEL_1", "UNSAFE", "MALICIOUS"):
            injection_score = raw_score
        elif "SAFE" in label or label in ("LABEL_0", "LEGIT", "BENIGN"):
            injection_score = 1.0 - raw_score
        else:
            # Fallback for generic outputs
            injection_score = raw_score

        return injection_score, label

    def scan(self, text: str, threshold: float = 0.80) -> ScanResult:
        """Scan input payload for prompt injection, jailbreaks, and heuristic exploit patterns.

        Args:
            text: Input string to analyze.
            threshold: Confidence threshold (0.0 to 1.0) above which text is flagged unsafe.

        Returns:
            Strict Pydantic v2 ScanResult.
        """
        start_time = time.perf_counter()

        # Handle empty, non-string, or whitespace inputs
        if text is None or not isinstance(text, str) or not text.strip():
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                is_safe=True,
                confidence_score=0.0,
                reasons=["Empty or whitespace input payload."],
                latency_ms=round(latency_ms, 3),
                tokens_analyzed=0,
                detected_heuristics=[],
            )

        # 1. Unicode normalization and de-obfuscation
        normalized_text = self.normalize_text(text)

        # 2. Fast heuristic pre-filtering
        heuristics_matched = self.check_heuristics(normalized_text)
        if heuristics_matched:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            tokens_count = len(normalized_text.split())
            return ScanResult(
                is_safe=False,
                confidence_score=1.0,
                reasons=[
                    f"Heuristic pattern detected: {rule}" for rule in heuristics_matched
                ],
                latency_ms=round(latency_ms, 3),
                tokens_analyzed=tokens_count,
                detected_heuristics=heuristics_matched,
            )

        # 3. Model Tokenization & Sliding-Window Analysis
        chunks = self._chunk_text_by_tokens(normalized_text)
        total_tokens = sum(chunk[2] for chunk in chunks) if len(chunks) == 1 else len(
            self.tokenizer.encode(normalized_text, add_special_tokens=False)
        )

        highest_injection_score = 0.0
        flagged_chunk_info = None
        reasons = []

        for chunk_idx, chunk_text, chunk_token_count in chunks:
            if not chunk_text.strip():
                continue
            pred = self.classification_pipeline(chunk_text)
            injection_score, label = self._parse_model_output(pred)

            if injection_score > highest_injection_score:
                highest_injection_score = injection_score

            if injection_score >= threshold:
                flagged_chunk_info = (chunk_idx, injection_score, label)
                reasons.append(
                    f"Prompt injection detected in window chunk #{chunk_idx} "
                    f"(confidence: {injection_score:.4f} >= threshold: {threshold:.2f}, label: {label})"
                )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        if flagged_chunk_info is not None:
            return ScanResult(
                is_safe=False,
                confidence_score=round(highest_injection_score, 4),
                reasons=reasons,
                latency_ms=round(latency_ms, 3),
                tokens_analyzed=total_tokens,
                detected_heuristics=[],
            )

        # Clean payload passed all checks
        safe_confidence = round(1.0 - highest_injection_score, 4)
        return ScanResult(
            is_safe=True,
            confidence_score=safe_confidence,
            reasons=["Passed heuristic rules and transformer safety classification."],
            latency_ms=round(latency_ms, 3),
            tokens_analyzed=total_tokens,
            detected_heuristics=[],
        )
