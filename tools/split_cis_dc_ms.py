#!/usr/bin/env python3
"""Split a Wazuh CIS Windows Server policy into a Member Server and a Domain Controller policy.

Usage: python3 tools/split_cis_dc_ms.py <policy.yml>...
Writes <policy>_ms.yml and <policy>_dc.yml next to each input; delete the original afterwards,
otherwise it still applies to both server types.

Checks tagged "(DC only)" or "(MS only)" in the CIS comment above them go to that variant only,
untagged checks go to both. A ProductType requirement lets the scanner pick the right variant.

`c:` rules are normalized so the scanner and the old SCAScanner run them the same: a nested
`powershell ...` call becomes the script itself (commands already run in PowerShell) and "literal"
becomes 'literal' (the old scanner strips double quotes). An unknown form stops the script.
"""
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

ROLE_TAG = re.compile(r'\((DC|MS) only\)', re.IGNORECASE)
COMMENT_PREFIX = '  # '     # CIS comment line above a check
CHECK_PREFIX = '  - id:'    # first line of a check
PRODUCT_TYPE_KEY = r'HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions -> ProductType'

# A one-line command rule as Wazuh writes it: `- 'c:<command> -> <condition>'`.
# Inside the YAML single quotes a literal ' is written as ''.
COMMAND_RULE = re.compile(r"^(?P<head>\s+- ')c:(?P<rule>.*)'(?P<eol>\s*)$")

# PowerShell flags that may precede -Command. They only matter when starting a new PowerShell,
# and the scanner already runs the command in one, so they can be dropped.
POWERSHELL_FLAG = re.compile(r'(?:-(?:NoProfile|NonInteractive|NoLogo)|-ExecutionPolicy\s+\S+)\s+', re.IGNORECASE)


@dataclass(frozen=True)
class Variant:
    role: str          # matches the (DC only) / (MS only) tag
    suffix: str        # appended to the policy file name and id
    label: str         # added to the policy name
    product_type: str  # ProductType registry value on this kind of server


VARIANTS = [
    Variant('MS', '_ms', 'Member Server', 'ServerNT'),
    Variant('DC', '_dc', 'Domain Controller', 'LanmanNT'),
]


def fail(message: str) -> NoReturn:
    """Stop with an error. Used instead of skipping, because a silent miss would produce a wrong policy."""
    sys.exit(f'error: {message}')


# ── Splitting the checks into variants ───────────────────────────────────────

@dataclass
class Block:
    """CIS comment line(s) plus the check below them. `check` is empty for comment-only blocks."""
    preamble: list[str]
    check: list[str]

    def for_variant(self, variant: Variant) -> list[str]:
        # Each comment line is kept or dropped on its own tag. The comment directly above the
        # check is the one that tags the check, so that one also decides about the check itself.
        preamble = [line for line in self.preamble if _applies(line, variant)]
        last_comment = self.preamble[-1] if self.preamble else ''
        check = self.check if _applies(last_comment, variant) else []
        return preamble + check


def _applies(comment: str, variant: Variant) -> bool:
    """True when the comment has no (DC only)/(MS only) tag, or the tag is for this variant."""
    match = ROLE_TAG.search(comment)
    return match is None or match.group(1).upper() == variant.role


def parse_blocks(lines: list[str]) -> list[Block]:
    """Group the lines below `checks:` into blocks, each starting at a CIS comment or a check."""
    blocks = [Block([], [])]
    for line in lines:
        # A comment or check starts a new block once the current block already holds its check.
        # Several comment lines in a row stay together, e.g. the "Not Implemented" entries.
        starts_block = line.startswith((COMMENT_PREFIX, CHECK_PREFIX))
        if starts_block and blocks[-1].check:
            blocks.append(Block([], []))
        current = blocks[-1]
        # From the `- id:` line on, everything (also the blank lines) belongs to the check.
        if line.startswith(CHECK_PREFIX) or current.check:
            current.check.append(line)
        else:
            current.preamble.append(line)
    return blocks


# ── Normalizing the `c:` command rules ───────────────────────────────────────

def unquote_script(text: str) -> str | None:
    """Turn one double-quoted string into its content, or None if it is not exactly that.

    The CIS rules use the cmd.exe convention: inside "..." a literal quote is written \\".
    """
    if len(text) < 2 or text[0] != '"' or text[-1] != '"':
        return None
    inner = text[1:-1]
    if '"' in inner.replace('\\"', ''):  # a bare quote means the string ends early
        return None
    return inner.replace('\\"', '"')


def unwrap_powershell(command: str) -> str:
    """Turn a nested "powershell ..." command into the script itself (the scanner already runs commands in PowerShell)."""
    match = re.fullmatch(r'powershell(?:\.exe)?\s+(.+)', command, re.IGNORECASE | re.DOTALL)
    if not match:
        fail(f'unsupported powershell rule (powershell is not at the start): {command[:100]}')
    rest = match.group(1).strip()

    # powershell -NoProfile -Command "<script>"
    if rest.startswith('-'):
        while flag := POWERSHELL_FLAG.match(rest):
            rest = rest[flag.end():]
        param = re.fullmatch(r'-(?:Command|c)\s+(.+)', rest, re.IGNORECASE | re.DOTALL)
        script = unquote_script(param.group(1).strip()) if param else None
        if script is None:
            fail(f'unsupported powershell parameters (expected -Command "<script>"): {command[:100]}')
        return script

    # powershell "<script>"
    if rest.startswith('"'):
        script = unquote_script(rest)
        if script is None:
            fail(f'unsupported quoted powershell script: {command[:100]}')
        return script

    # powershell <script>
    return rest


def to_single_quotes(command: str) -> str:
    """Rewrite "literal" as 'literal': the old SCAScanner strips double quotes from commands, single quotes survive."""
    out: list[str] = []
    i = 0
    while i < len(command):
        if command[i] == "'":
            # Copy an existing single-quoted string as is. Inside it, '' is an escaped quote,
            # so a quote followed by another quote does not end the string.
            end = i + 1
            while end < len(command) and not (command[end] == "'" and command[end + 1:end + 2] != "'"):
                end += 2 if command[end] == "'" else 1
            out.append(command[i:end + 1])
            i = end + 1
        elif command[i] == '"':
            end = command.find('"', i + 1)
            if end == -1 or command[end + 1:end + 2] == '"':  # "" is PowerShell's escaped quote
                fail(f'cannot rewrite double quotes (unterminated or doubled): {command[:100]}')
            literal = command[i + 1:end]
            # "..." expands $variables and honours backtick escapes, '...' does not. Only rewrite
            # strings where that makes no difference.
            if '$' in literal or '`' in literal:
                fail(f'cannot rewrite an expandable string to single quotes: {command[:100]}')
            out.append("'" + literal.replace("'", "''") + "'")
            i = end + 1
        else:
            out.append(command[i])
            i += 1
    return ''.join(out)


def fix_command_rules(lines: list[str]) -> tuple[list[str], int]:
    """Make `c:` rules run the same in the scanner and the old SCAScanner: direct PowerShell, single quotes only.

    Returns the new lines and the number of rules that changed.
    """
    fixed: list[str] = []
    count = 0
    for line in lines:
        match = COMMAND_RULE.match(line)
        if not match:
            fixed.append(line)
            continue

        # Work on the real rule text: undo the YAML '' escaping, and only touch the command,
        # not the match condition after ' -> '.
        command, arrow, condition = match['rule'].replace("''", "'").partition(' -> ')
        script = unwrap_powershell(command) if 'powershell' in command.lower() else command
        script = to_single_quotes(script)

        if 'powershell' in script.lower():
            fail(f'powershell is still present after rewriting: {script[:100]}')
        if '"' in script:
            # Only possible inside a single-quoted string; the old scanner would still strip it.
            fail(f'a double quote inside a single-quoted string cannot be made safe: {script[:100]}')

        rule = (script + arrow + condition).replace("'", "''")  # back to YAML escaping
        new_line = f"{match['head']}c:{rule}'{match['eol']}"
        fixed.append(new_line)
        count += new_line != line

    # Rules in another YAML form (`- c:...` or `- "c:..."`) are not handled above. Refuse them
    # when they call powershell, instead of leaving a rule that only works in one scanner.
    leftover = next((line for line in fixed if re.match(r"^\s+- [^']*c:.*powershell", line, re.IGNORECASE)), None)
    if leftover:
        fail(f'powershell rule in an unsupported YAML form: {leftover.strip()[:100]}')
    return fixed, count


# ── Writing the variants ─────────────────────────────────────────────────────

def substitute_once(pattern: str, replacement: str | Callable[[re.Match[str]], str], header: str, what: str) -> str:
    """Replace the first match; fail loudly, since a silent miss would leave a variant without its ProductType rule."""
    result, count = re.subn(pattern, replacement, header, count=1)
    if count == 0:
        fail(f'{what} not found in the policy header (unexpected Wazuh format); nothing written')
    return result


def rewrite_header(header: str, source: Path, variant: Variant) -> str:
    """Give the variant its own id, file name and policy name, and add the ProductType requirement."""
    name = source.stem + variant.suffix
    # re.escape for the literal parts; the lambdas keep backslashes in `name` from being read as group references.
    header = substitute_once(re.escape(f'id: "{source.stem}"'), lambda _: f'id: "{name}"', header, 'policy id')
    header = substitute_once(re.escape(f'file: "{source.name}"'), lambda _: f'file: "{name}.yml"', header, 'policy file')
    # "CIS ... Benchmark v2.0.0" -> "CIS ... Member Server Benchmark v2.0.0"
    header = substitute_once(r'(  name: "CIS [^"]*?)(Benchmark)', rf'\1{variant.label} \2', header, 'policy name')
    rule = f"    - 'r:{PRODUCT_TYPE_KEY} -> r:^{variant.product_type}$'\n"
    # Append after the existing requirement rule (the Windows version check); all rules must hold.
    return substitute_once(r'(  rules:\n    - [^\n]*\n)', lambda m: m.group(1) + rule, header, 'requirements rule')


def split_policy(source: Path) -> None:
    # read_text turns CRLF into LF, so the line matching below also works for a CRLF checkout.
    lines, fixed = fix_command_rules(source.read_text(encoding='utf-8').split('\n'))
    print(f'{source.name}: {fixed} command rule(s) rewritten (direct PowerShell, single quotes)')
    if 'checks:' not in lines:
        fail(f"no top-level 'checks:' line in {source.name} (unexpected Wazuh format); nothing written")
    checks_at = lines.index('checks:')
    header = '\n'.join(lines[:checks_at + 1])
    blocks = parse_blocks(lines[checks_at + 1:])

    # Build every variant first, so a failure leaves no half-written output behind.
    outputs: dict[Path, str] = {}
    for variant in VARIANTS:
        body = [line for block in blocks for line in block.for_variant(variant)]
        text = rewrite_header(header, source, variant) + '\n' + '\n'.join(body)
        outputs[source.with_name(source.stem + variant.suffix + '.yml')] = text

    for target, text in outputs.items():
        target.write_text(text, encoding='utf-8', newline='\n')  # LF, like the Wazuh originals


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for path in sys.argv[1:]:
        split_policy(Path(path))
