#!/usr/bin/env python3
"""Apply Polaris display fixes to the external WebUI before its static build."""
import hashlib
from pathlib import Path
import sys

EDITS = {
    'src/components/dashboard/upstream-servers/upstream-servers-table.tsx': [
        ('if (avgTime < 0)', 'if (!Number.isFinite(avgTime) || avgTime < 0)'),
        ('<span>{avgTime} ms</span>', '<span>{avgTime.toFixed(2)} ms</span>'),
    ],
    'src/components/dashboard/overview/upstream-servers.tsx': [
        ('<TableCell>{server.avg_time}</TableCell>',
         "<TableCell>{!Number.isFinite(server.avg_time) || server.avg_time < 0 ? 'N/A' : `${server.avg_time.toFixed(2)} ms`}</TableCell>"),
    ],
}


def prepare(root):
    pending = []
    digest = hashlib.sha256()
    for relative, edits in EDITS.items():
        path = root / relative
        original = text = path.read_text()
        for old, new in edits:
            if text.count(old) == 1 and new not in text:
                text = text.replace(old, new)
            elif old in text or text.count(new) != 1:
                raise ValueError(f'Unexpected WebUI source: {relative}')
        pending.append((path, original, text))
        digest.update(relative.encode() + b'\0' + text.encode() + b'\0')
    # Validate every input before modifying either source file.
    for path, original, text in pending:
        if text != original:
            path.write_text(text)
    return digest.hexdigest()


if __name__ == '__main__':
    print(prepare(Path(sys.argv[1])))
