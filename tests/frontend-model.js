'use strict';

/* Run: node tests/frontend-model.js. No DOM or RPC wiring assertions. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const model = new Function('baseclass', fs.readFileSync(path.join(__dirname,
	'../htdocs/luci-static/resources/dns-monitor/model.js'), 'utf8'))({ extend: value => value });

function record(id, domain = 'Example.COM', type = 'A', client = '192.0.2.1') {
	return { id, timestamp: 1700000000 + id, client_ip: client, domain, record_type: type };
}
function response(epoch, records, options = {}) {
	const oldest = options.oldest ?? (records[0]?.id || 0);
	const newest = options.newest ?? (records.at(-1)?.id || 0);
	return { epoch, reset: !!options.reset, oldest, newest, cursor: options.cursor ?? newest,
		more: !!options.more, records,
		status: { epoch, oldest, newest, max_records: options.cap ?? 10000,
			retained: records.length, active: true, client: '192.0.2.1', captured: newest, expires: 1700003600 } };
}

{
	const store = model.createStore();
	model.ingest(store, response('one', [ record(1), record(2) ], { newest: 4, cursor: 2, more: true }));
	assert.equal(store.cursor, 2, 'cursor follows the last delivered id, not the newest ring id');
	model.ingest(store, response('one', [ record(2), record(3), record(4) ], { oldest: 2 }));
	assert.deepEqual(store.records.map(r => r.id), [ 2, 3, 4 ], 'eviction prunes stale ids and overlap does not duplicate requests');
	model.ingest(store, response('one', [ record(5) ], { oldest: 3, reset: true, cursor: 5 }));
	assert.deepEqual(store.records.map(r => r.id), [ 5 ], 'cursor eviction reset discards obsolete browser history');
	model.ingest(store, response('two', [ record(1, 'new.example') ]));
	assert.deepEqual(store.records.map(r => r.domain), [ 'new.example' ], 'new epoch allows reused ids without old-session leakage');
	model.updateStatus(store, response('three', []).status);
	assert.equal(store.cursor, 0);
	assert.equal(store.records.length, 0, 'clear status immediately clears browser history');
}

{
	const store = model.createStore();
	model.ingest(store, response('cap', [ record(1), record(2), record(3), record(4) ], { cap: 2 }));
	assert.deepEqual(store.records.map(r => r.id), [ 3, 4 ]);
	const many = Array.from({ length: 10050 }, (_, index) => record(index + 1));
	model.ingest(store, response('large', many, { cap: 20000 }));
	assert.equal(store.records.length, 10000, 'browser never retains over ten thousand records');
	assert.equal(store.records[0].id, 51);
}

{
	const records = [ record(1), record(2, 'example.com', 'AAAA'), record(3, 'a.example.com'),
		record(4, 'EXAMPLE.com', 'A', '2001:db8::1'), record(5, 'other.example') ];
	const groups = model.rows(records, true, 'count-desc');
	assert.equal(groups[0].domain, 'Example.COM', 'first spelling is retained');
	assert.equal(groups[0].count, 3, 'case-insensitive grouping counts repeated request records');
	assert.equal(groups.length, 3, 'subdomains are not collapsed into parent names');
	assert.equal(groups[0].timestamp, records[3].timestamp);
	assert.equal(groups[0].record_type, 'A, AAAA');
	assert.equal(groups[0].client_ip, '192.0.2.1, 2001:db8::1');
	const filtered = model.filterRecords(records, { search: 'EXAMPLE.COM', client: '192.0.2.1', type: 'A' });
	assert.deepEqual(filtered.map(r => r.id), [ 1, 3 ]);
	assert.equal(model.rows(filtered, true, 'count-desc')[0].count, 1, 'group counts are from filtered retained requests only');
	assert.deepEqual(model.rows(records, false, 'time-asc').map(r => r.id), [ 1, 2, 3, 4, 5 ]);
	assert.equal(model.rows(records, true, 'time-desc')[0].domain, 'other.example');
}

{
	const records = Array.from({ length: 140 }, (_, index) => record(index + 1, 'host' + index + '.example'));
	const selected = new Set([ 'host0.example', 'host139.example' ]);
	assert.deepEqual(model.domains(records, selected), [ 'host0.example', 'host139.example' ], 'selection includes records beyond the first table page');
	assert.equal(model.domains(records).length, 140, 'all-filtered export is independent of pagination');
	assert.equal(model.exportData(records, 'txt', selected), 'host0.example\nhost139.example\n');
	assert.equal(model.domains(records.slice(0, 50), selected).length, 1, 'hidden by filters is not exported');
	const mixed = [ record(1, 'Example.COM'), record(2, 'example.com') ];
	assert.equal(model.exportData(mixed, 'txt', new Set([ 'example.com' ])), 'Example.COM\n');
	assert.equal(model.exportData(mixed, 'csv', new Set([ 'example.com' ])).split('\r\n').length, 4, 'CSV contains every selected-domain request, not grouped rows');
	const unsafe = record(1, 'odd,"name\n.example', 'A,"TXT');
	assert.equal(model.exportData([ unsafe ], 'csv'),
		'timestamp,client_ip,domain,record_type\r\n"1700000001","192.0.2.1","odd,""name\n.example","A,""TXT"\r\n');
	assert.equal(model.exportData([], 'txt'), '');
	assert.equal(model.exportData([], 'csv'), 'timestamp,client_ip,domain,record_type\r\n');
}

console.log('Frontend history, grouping, filtering, selection and export behavior passed.');
