"""Token Sequencer — analyzes randomness of tokens/session IDs.

Like Burp Sequencer but CLI. Measures entropy, character distribution,
and predictability of tokens.

Usage:
    from hunter.core.sequencer import Sequencer
    
    s = Sequencer()
    tokens = ["abc123", "def456", "ghi789", ...]  # Collect 100+ tokens
    result = s.analyze(tokens)
    print(result['entropy'])  # 4.2 bits per char (high = random)
    print(result['predictable'])  # False
"""
import math
import collections
from dataclasses import dataclass


@dataclass
class SequencerResult:
    """Token randomness analysis result."""
    count: int
    min_length: int
    max_length: int
    avg_length: float
    unique_count: int
    uniqueness_ratio: float
    entropy_per_char: float
    total_entropy: float
    char_distribution: dict
    predictable: bool
    issues: list

    def to_dict(self):
        return {
            "count": self.count,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "avg_length": round(self.avg_length, 2),
            "unique_count": self.unique_count,
            "uniqueness_ratio": round(self.uniqueness_ratio, 3),
            "entropy_per_char": round(self.entropy_per_char, 3),
            "total_entropy": round(self.total_entropy, 2),
            "predictable": self.predictable,
            "issues": self.issues,
        }


class Sequencer:
    """Token randomness analyzer — like Burp Sequencer.
    
    Measures:
    - Entropy (bits per character)
    - Character distribution uniformity
    - Uniqueness ratio
    - Length variance
    - Sequential patterns
    """

    def analyze(self, tokens: list[str]) -> dict:
        """Analyze a list of tokens for randomness.
        
        Args:
            tokens: List of token strings (100+ recommended)
            
        Returns:
            Dict with entropy, predictability, issues
        """
        if not tokens:
            return {"error": "No tokens provided"}

        tokens = [str(t) for t in tokens if t]
        count = len(tokens)

        if count < 10:
            return {"error": f"Need 10+ tokens, got {count}. Results unreliable."}

        # Length analysis
        lengths = [len(t) for t in tokens]
        min_len = min(lengths)
        max_len = max(lengths)
        avg_len = sum(lengths) / count

        # Uniqueness
        unique = set(tokens)
        unique_ratio = len(unique) / count

        # Character frequency
        all_chars = "".join(tokens)
        char_freq = collections.Counter(all_chars)
        total_chars = len(all_chars)

        # Shannon entropy
        entropy = 0.0
        for char, freq in char_freq.items():
            p = freq / total_chars
            if p > 0:
                entropy -= p * math.log2(p)

        total_entropy = entropy * avg_len

        # Issues detection
        issues = []

        if unique_ratio < 0.95:
            issues.append(f"Low uniqueness: {unique_ratio:.1%} unique tokens")

        if entropy < 2.0:
            issues.append(f"Low entropy: {entropy:.2f} bits/char (should be >3.0)")

        if max_len - min_len > 2:
            issues.append(f"Variable length: {min_len}-{max_len} chars")

        # Check for sequential patterns
        if self._has_sequential(tokens):
            issues.append("Sequential pattern detected")

        # Check for repeated substrings
        if self._has_repeated_patterns(tokens):
            issues.append("Repeated patterns detected")

        # Check for timestamp-like patterns
        if self._has_timestamp_pattern(tokens):
            issues.append("Timestamp-based pattern detected")

        predictable = len(issues) > 0 or entropy < 3.0

        return {
            "count": count,
            "min_length": min_len,
            "max_length": max_len,
            "avg_length": round(avg_len, 2),
            "unique_count": len(unique),
            "uniqueness_ratio": round(unique_ratio, 3),
            "entropy_per_char": round(entropy, 3),
            "total_entropy": round(total_entropy, 2),
            "char_distribution": dict(char_freq.most_common(20)),
            "predictable": predictable,
            "issues": issues,
            "verdict": "PREDICTABLE" if predictable else "RANDOM",
        }

    def _has_sequential(self, tokens: list[str]) -> bool:
        """Check for sequential patterns."""
        if len(tokens) < 3:
            return False
        # Check if numeric parts increment
        for i in range(min(10, len(tokens) - 2)):
            try:
                n1 = int(''.join(c for c in tokens[i] if c.isdigit()))
                n2 = int(''.join(c for c in tokens[i+1] if c.isdigit()))
                n3 = int(''.join(c for c in tokens[i+2] if c.isdigit()))
                if n2 - n1 == n3 - n2 and n2 - n1 > 0:
                    return True
            except:
                continue
        return False

    def _has_repeated_patterns(self, tokens: list[str]) -> bool:
        """Check for repeated substrings across tokens."""
        if len(tokens) < 10:
            return False
        # Check if all tokens share a common prefix/suffix
        prefix = tokens[0][:4]
        suffix = tokens[0][-4:]
        prefix_count = sum(1 for t in tokens if t.startswith(prefix))
        suffix_count = sum(1 for t in tokens if t.endswith(suffix))
        return prefix_count > len(tokens) * 0.8 or suffix_count > len(tokens) * 0.8

    def _has_timestamp_pattern(self, tokens: list[str]) -> bool:
        """Check for timestamp-based patterns."""
        if len(tokens) < 5:
            return False
        # Check for monotonically increasing numbers
        nums = []
        for t in tokens[:20]:
            digits = ''.join(c for c in t if c.isdigit())
            if digits:
                try:
                    nums.append(int(digits))
                except:
                    pass
        if len(nums) >= 5:
            increasing = all(nums[i] <= nums[i+1] for i in range(len(nums)-1))
            return increasing
        return False
