'use strict';
'require baseclass';

/* Pure history operations shared by the view and its behavior tests. */
function domainKey(domain) {
	return String(domain).toLowerCase();
}

function createStore() {
	return { epoch: '', cursor: 0, records: [], status: null };
}

function updateStatus(store, status) {
	var changed = store.epoch !== status.epoch;
	if (changed) {
		store.epoch = status.epoch;
		store.cursor = 0;
		store.records = [];
	}
	store.status = status;
	var cap = Math.max(1, Math.min(10000, Number(status.max_records) || 10000));
	store.records = store.records.filter(function(record) { return record.id >= status.oldest; }).slice(-cap);
	return changed;
}

function ingest(store, response) {
	var changed = updateStatus(store, response.status);
	if (response.reset || store.epoch !== response.epoch) {
		store.records = [];
		store.cursor = 0;
		changed = true;
	}
	store.epoch = response.epoch;
	var known = new Set(store.records.map(function(record) { return record.id; }));
	response.records.forEach(function(record) {
		if (record.id >= response.oldest && !known.has(record.id)) {
			store.records.push(record);
			known.add(record.id);
		}
	});
	store.cursor = response.cursor;
	var cap = Math.max(1, Math.min(10000, Number(response.status.max_records) || 10000));
	store.records = store.records.filter(function(record) { return record.id >= response.oldest; })
		.sort(function(a, b) { return a.id - b.id; }).slice(-cap);
	return changed;
}

function filterRecords(records, filters) {
	var search = String(filters.search || '').trim().toLowerCase();
	return records.filter(function(record) {
		return (!search || domainKey(record.domain).indexOf(search) !== -1) &&
			(!filters.client || record.client_ip === filters.client) &&
			(!filters.type || record.record_type === filters.type);
	});
}

function rows(records, unique, sort) {
	var result;
	if (unique) {
		var groups = new Map();
		records.forEach(function(record) {
			var key = domainKey(record.domain), group = groups.get(key);
			if (!group) {
				group = { key: key, domain: record.domain, timestamp: record.timestamp,
					count: 0, clients: new Set(), types: new Set(), id: record.id };
				groups.set(key, group);
			}
			group.count++;
			group.clients.add(record.client_ip);
			group.types.add(record.record_type);
			if (record.timestamp > group.timestamp || record.id > group.id) {
				group.timestamp = record.timestamp;
				group.id = record.id;
			}
		});
		result = Array.from(groups.values()).map(function(group) {
			group.client_ip = Array.from(group.clients).sort().join(', ');
			group.record_type = Array.from(group.types).sort().join(', ');
			return group;
		});
	}
	else {
		result = records.map(function(record) {
			return Object.assign({ key: domainKey(record.domain), count: 1 }, record);
		});
	}
	var direction = /-asc$/.test(sort) ? 1 : -1;
	result.sort(function(a, b) {
		var difference = /^count-/.test(sort) ? a.count - b.count : a.timestamp - b.timestamp;
		return direction * difference || b.id - a.id || a.key.localeCompare(b.key);
	});
	return result;
}

function domains(records, selected) {
	var seen = new Set(), result = [];
	records.forEach(function(record) {
		var key = domainKey(record.domain);
		if ((!selected || selected.has(key)) && !seen.has(key)) {
			seen.add(key);
			result.push(record.domain);
		}
	});
	return result;
}

function csvCell(value) {
	return '"' + String(value).replace(/"/g, '""') + '"';
}

function exportData(records, format, selected) {
	if (format === 'txt') {
		var names = domains(records, selected);
		return names.join('\n') + (names.length ? '\n' : '');
	}
	var matching = records.filter(function(record) { return !selected || selected.has(domainKey(record.domain)); });
	return 'timestamp,client_ip,domain,record_type\r\n' + matching.map(function(record) {
		return [ record.timestamp, record.client_ip, record.domain, record.record_type ].map(csvCell).join(',');
	}).join('\r\n') + (matching.length ? '\r\n' : '');
}

return baseclass.extend({
	createStore: createStore,
	updateStatus: updateStatus,
	ingest: ingest,
	filterRecords: filterRecords,
	rows: rows,
	domains: domains,
	domainKey: domainKey,
	exportData: exportData
});
