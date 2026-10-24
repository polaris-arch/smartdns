#!/usr/bin/env node
'use strict';
// Exercise the actual patched getRowId option with the actual TanStack row
// model used by MaterialReactTable. This is a bounded source/dependency test,
// not a replacement for the real browser route/refresh acceptance test.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const [source, apiFile, report] = process.argv.slice(2);
assert(source && apiFile && report, 'usage: test-table-identity.cjs PREPARED_SOURCE ACTUAL_API_JSON REPORT');
for (const line of fs.readFileSync(path.join(__dirname, 'postimage.sha256'), 'utf8').trim().split('\n')) {
  const [sha, file] = line.split('  ');
  assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(source, file))).digest('hex'), sha);
}
const text = fs.readFileSync(path.join(source, 'src/components/dashboard/upstream-servers/upstream-servers-table.tsx'), 'utf8');
const matches = [...text.matchAll(/^\s*getRowId: (.+),$/gm)];
assert.equal(matches.length, 1, 'read the sole actual useMaterialReactTable option');
const getRowId = Function('"use strict"; return (' + matches[0][1] + ');')();
const { createTable, getCoreRowModel } = createRequire(path.join(path.resolve(source), 'package.json'))('@tanstack/table-core');
const data = JSON.parse(fs.readFileSync(apiFile, 'utf8')).upstream_server_list;
const options = { columns: [{ accessorKey: 'host' }], state: {}, onStateChange() {}, renderFallbackValue: null, getCoreRowModel: getCoreRowModel() };
const table = createTable({ ...options, data, getRowId });
function check(rows, expectedData) {
  assert.equal(new Set(rows.map(row => row.id)).size, rows.length);
  rows.forEach((row, index) => {
    assert.equal(row.original, expectedData[index]);
    assert.equal(row.id, row.original.service_id || String(index));
  });
}
check(table.getCoreRowModel().rows, data);
const before = table.getCoreRowModel().rows.filter(row => row.original.service_id).map(row => row.id).sort();
const reordered = data.slice().reverse();
table.setOptions(old => ({ ...old, data: reordered }));
check(table.getCoreRowModel().rows, reordered);
assert.deepEqual(table.getCoreRowModel().rows.filter(row => row.original.service_id).map(row => row.id).sort(), before);
// Truly legacy rows without an ID retain the default-index fallback. Modern
// ordinary endpoints use their canonical native ID, including across reorder.
const ordinary = data.find(row => !row.pool_enabled);
const ordinaryData = [{...ordinary, service_id: undefined}, {...ordinary, service_id: undefined}];
const baseline = createTable({ ...options, data: ordinaryData });
const candidate = createTable({ ...options, data: ordinaryData, getRowId });
assert.deepEqual(candidate.getCoreRowModel().rows.map(row => row.id), baseline.getCoreRowModel().rows.map(row => row.id));
fs.writeFileSync(report, JSON.stringify({ passed: true, service_ids: before, ordinary_ids: candidate.getCoreRowModel().rows.map(row => row.id), source_option: matches[0][1], note: 'Actual patched option and actual TanStack row model; browser assertions are separate.' }, null, 2) + '\n');
