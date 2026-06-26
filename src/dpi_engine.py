import re
from dataclasses import dataclass
from typing import Optional

# Maximum buffered bytes per direction per flow (8KB covers most HTTP requests)
MAX_BUFFER_BYTES = 8192
# Maximum regex pattern via REST (prevents pathologically large patterns)
MAX_PATTERN_LEN = 512
# Maximum user patterns
MAX_USER_PATTERNS = 50

# Heuristic blocklist for regex constructs that risk catastrophic backtracking (time-based check would be stronger)
DANGEROUS_RE = re.compile(
    r'\)\+'             # group followed by + [e.g. (X)+]
    r'|\)\*'            # group followed by * [e.g. (X)*]
    r'|\)\{[^}]*\}'     # group followed by {n} [e.g. (X){5,}]
)

# Built-in DPI patterns
_BUILTIN_DPI_PATTERNS = [
    ('SQL_INJECTION',
     rb'union\s+select|drop\s+table|or\s+1\s*=\s*1|--|;\s*drop',
     'SQL injection patterns: UNION SELECT, DROP TABLE, OR 1=1, comment sequences'),

    ('SHELLCODE_NOP_SLED',
     rb'\x90{16,}',
     'x86 NOP sled (16+ consecutive 0x90 bytes) - likely shellcode prefix'),

    ('XSS_SCRIPT_TAG',
     rb'<\s*script[^>]{0,100}>',
     'Cross-site scripting: <script> tag injection'),

    ('PATH_TRAVERSAL',
     rb'(?:\.\.[\\/]){2,}|(?:%2e%2e%2f){2,}',
     'Directory traversal attempts (../../ or URL-encoded)'),

    ('CMD_INJECTION',
     rb'(?:;|\|\||&&|`|\$\()\s*(?:ls|cat|id|whoami|wget|curl|bash|sh|nc|python)',
     'Shell command injection chained with common commands'),

    ('FTP_CLEARTEXT_CREDS',
     rb'(?:USER|PASS)\s+\S+\r\n',
     'FTP credentials transmitted in cleartext (alerts on compliance issue)'),
]


@dataclass
class DPIPattern:
    """DPI signature"""
    name: str               # unique identifier, used as the REST delete key
    raw_pattern: str        # original pattern string for display and serialization
    compiled: re.Pattern    # pre-compiled bytes-mode regex
    description: str = ''   # human-readable text shown in the GUI
    enabled: bool = True    # runtime toggle without removing the pattern
    builtin: bool = False   # built-in patterns cannot be deleted via REST


@dataclass
class DPIVerdict:
    """Result of DPIEngine.inspect()"""
    matched: bool
    pattern_name: Optional[str] = None
    pattern_description: Optional[str] = None


class DPIEngine:
    def __init__(self):
        self.patterns: list[DPIPattern] = []
        self._init_builtin_patterns()


    def _init_builtin_patterns(self):
        """
        Compile and register the builtin DPI patterns (called once from init in Firewall_App).
        """
        for name, raw_pattern, description in _BUILTIN_DPI_PATTERNS:
            compiled = re.compile(raw_pattern, re.IGNORECASE | re.DOTALL)
            self.patterns.append(
                DPIPattern(
                    name=name,
                    raw_pattern=raw_pattern.decode('utf-8', errors='replace'),
                    compiled=compiled,
                    description=description,
                    enabled=True,
                    builtin=True
                )
            )

    def inspect(self, payload: bytes) -> DPIVerdict:
        """
        Runs all enabled patterns against supplied bytes and returns the FIRST match
        """

        if not payload:
            return DPIVerdict(matched=False)

        for pattern in self.patterns:
            if not pattern.enabled:
                continue
            if pattern.compiled.search(payload):
                return DPIVerdict(matched=True,
                                  pattern_name=pattern.name,
                                  pattern_description=pattern.description, )

        return DPIVerdict(matched=False)

    def add_pattern(self, name: str, raw_pattern: str, description: str = "") -> DPIPattern:
        """
        Validate and add user-defined pattern
        """
        name = name.strip()
        if not name:
            raise ValueError('Pattern name is required')
        if len(name) > 64:
            raise ValueError('Pattern name is too long')
        if not re.match(r'^[A-Za-z0-9_\-]+$', name):
            raise ValueError('Pattern name is invalid')
        if any(p.name == name for p in self.patterns):
            raise ValueError(f'Pattern "{name}" already exists')

        if not raw_pattern or not raw_pattern.strip():
            raise ValueError('Pattern body is required')
        if len(raw_pattern) > MAX_PATTERN_LEN:
            raise ValueError(f'Pattern body is too long (max {MAX_PATTERN_LEN} chars)')
        if DANGEROUS_RE.search(raw_pattern):
            raise ValueError(f'Pattern contains constructs that risk catastrophic backtracking. Use a simpler pattern')

        user_count = sum(1 for p in self.patterns if not p.builtin)
        if user_count >= MAX_USER_PATTERNS:
            raise ValueError(f'User pattern limit reached (max {MAX_USER_PATTERNS})')

        try:
            compiled = re.compile(raw_pattern.encode('utf-8'), re.IGNORECASE | re.DOTALL)
        except re.error as e:
            raise ValueError(f'Invalid regex syntax: {e}')

        pattern = DPIPattern(
            name=name,
            raw_pattern=raw_pattern,
            compiled=compiled,
            description=description,
            enabled=True,
            builtin=False,
        )
        self.patterns.append(pattern)
        return pattern

    def remove_pattern(self, name: str) -> bool:
        """
        Remove a user-defined pattern by name.
        """
        target = next((p for p in self.patterns if p.name == name), None)
        if target is None:
            return False
        if target.builtin:
            raise ValueError(f'Pattern "{name}" is built-in and cannot be removed')

        self.patterns = [p for p in self.patterns if p.name != name]
        return True

    def list_patterns(self) -> list[dict]:
        """
        Serialize patterns into JSON-safe dicts
        """

        return [
            {
                'name': p.name,
                'raw_pattern': p.raw_pattern,
                'description': p.description,
                'enabled': p.enabled,
                'builtin': p.builtin,
            }
            for p in self.patterns
        ]
