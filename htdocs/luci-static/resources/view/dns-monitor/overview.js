'use strict';
'require view';
'require rpc';
'require poll';
'require ui';
'require validation';
'require dns-monitor.model as model';

var callStatus = rpc.declare({ object: 'dns-monitor', method: 'status', expect: {}, reject: true });
var callClients = rpc.declare({ object: 'dns-monitor', method: 'get_clients', expect: {}, reject: true });
var callQueries = rpc.declare({ object: 'dns-monitor', method: 'get_queries', params: [ 'epoch', 'cursor', 'limit' ], expect: {}, reject: true });
var callStart = rpc.declare({ object: 'dns-monitor', method: 'start', params: [ 'client' ], expect: {}, reject: true });
var callStop = rpc.declare({ object: 'dns-monitor', method: 'stop', expect: {}, reject: true });
var callClear = rpc.declare({ object: 'dns-monitor', method: 'clear', expect: {}, reject: true });
var callLists = rpc.declare({ object: 'dns-monitor.ruantiblock', method: 'lists', expect: {}, reject: true });
var callAdd = rpc.declare({ object: 'dns-monitor.ruantiblock', method: 'add', params: [ 'list', 'domains' ], expect: {}, reject: true });

function checked(result) {
	if (!result || typeof(result) !== 'object')
		throw new Error(_('The service returned an invalid response.'));
	if (result.error)
		throw new Error(result.error);
	return result;
}

function message(error) {
	return error && error.message ? error.message : String(error);
}

/* LuCI E() treats scalar children as HTML; arrays create literal text nodes. */
function textNode(tag, attributes, children) {
	return E(tag, attributes || {}, children == null ? [] : Array.isArray(children) ? children : [ children ]);
}

function button(label, handler, style) {
	return textNode('button', { 'class': 'cbi-button ' + (style || ''), 'type': 'button', 'click': handler }, label);
}

function option(value, text, disabled) {
	var node = textNode('option', { 'value': value }, text);
	node.disabled = !!disabled;
	return node;
}

function field(label, input) {
	return textNode('label', { 'class': 'dns-monitor-field' }, [ textNode('span', {}, label), input ]);
}

function time(value) {
	return value ? new Date(value * 1000).toLocaleString() : '\u2014';
}

var clientStates = {
	lease: _('DHCP lease (connection not verified)'),
	neighbour: _('Neighbor entry (connection not verified)'),
	'lease+neighbour': _('DHCP lease and neighbor entry (connection not verified)'),
	unknown: _('Connection unknown')
};

return view.extend({
	load: function() {
		return Promise.all([
			callStatus().then(checked).then(function(status) { return { status: status }; }, function(error) { return { error: message(error) }; }),
			callClients().then(checked).then(function(result) { return result.clients || []; }, function() { return null; }),
			callLists().then(checked).then(function(result) { return result; }, function(error) {
				return { available: false, lists: [], error: message(error) };
			})
		]);
	},

	render: function(data) {
		var self = this;
		this.store = model.createStore();
		this.selected = new Set();
		this.page = 0;
		this.pageSize = 50;
		this.readonly = L.hasViewPermission() !== true;
		this.clients = data[1];
		this.integration = data[2];
		this.actionBusy = false;
		this.tickPromise = null;
		this.more = false;
		this.pollError = '';
		this.lastClientRefresh = Date.now();

		this.device = textNode('select', { 'id': 'dns-monitor-device', 'change': function() {
			self.manual.disabled = self.readonly || !!self.device.value;
			self.updateControls();
		} });
		this.manual = textNode('input', { 'id': 'dns-monitor-address', 'type': 'text', 'placeholder': _('IPv4 or IPv6 address'),
			'input': function() { self.updateControls(); } });
		this.clientInfo = textNode('p', { 'class': 'dns-monitor-muted' });
		this.clientWarning = textNode('p', { 'class': 'dns-monitor-muted' }, _('A DHCP lease or neighbor entry does not prove that a device is currently connected. Monitoring matches the chosen IP address only, not every address belonging to its MAC.'));
		this.refreshClients = button(_('Refresh devices'), function() { self.refreshDevices(); });
		this.startButton = button(_('Start monitoring'), function() { self.confirmMonitoring(true); }, 'cbi-button-action');
		this.stopButton = button(_('Stop monitoring'), function() { self.confirmMonitoring(false); }, 'cbi-button-negative');
		this.clearButton = button(_('Clear history'), function() { self.confirmClear(); });
		this.statusBox = textNode('div', { 'role': 'status', 'aria-live': 'polite' });
		this.errorBox = textNode('p', { 'class': 'alert-message warning', 'role': 'alert', 'hidden': true });
		this.summary = textNode('p', { 'role': 'status' });
		this.selectionSummary = textNode('span', { 'class': 'dns-monitor-muted' });

		this.search = textNode('input', { 'type': 'search', 'placeholder': _('Search domain'), 'input': function() { self.resetPage(); } });
		this.filterClient = textNode('select', { 'change': function() { self.resetPage(); } });
		this.filterType = textNode('select', { 'change': function() { self.resetPage(); } });
		this.mode = textNode('select', { 'change': function() { self.resetPage(); } }, [
			option('unique', _('Unique domains (case-insensitive)')), option('raw', _('Every request'))
		]);
		this.sort = textNode('select', { 'change': function() { self.resetPage(); } }, [
			option('time-desc', _('Time: newest first')), option('time-asc', _('Time: oldest first')),
			option('count-desc', _('Count: highest first')), option('count-asc', _('Count: lowest first'))
		]);
		this.pageSelect = textNode('select', { 'change': function() { self.pageSize = Number(self.pageSelect.value); self.resetPage(); } }, [
			option('25', '25'), option('50', '50'), option('100', '100')
		]);
		this.pageSelect.value = '50';
		this.tableBody = textNode('tbody');
		this.table = textNode('table', { 'class': 'table dns-monitor-table' }, [
			textNode('thead', {}, textNode('tr', { 'class': 'tr table-titles' }, [
				textNode('th', { 'class': 'th' }, _('Select')), textNode('th', { 'class': 'th' }, _('Time / last request')),
				textNode('th', { 'class': 'th' }, _('Domain')), textNode('th', { 'class': 'th' }, _('Client IP')),
				textNode('th', { 'class': 'th' }, _('Record type')), textNode('th', { 'class': 'th' }, _('Requests'))
			])), this.tableBody
		]);
		this.previous = button(_('Previous'), function() { self.page--; self.renderHistory(); });
		this.next = button(_('Next'), function() { self.page++; self.renderHistory(); });
		this.pageLabel = textNode('span');
		this.selectFiltered = button(_('Select all filtered domains'), function() {
			model.domains(self.filtered).forEach(function(domain) { self.selected.add(model.domainKey(domain)); });
			self.renderHistory();
		});
		this.clearSelection = button(_('Clear selection'), function() { self.selected.clear(); self.renderHistory(); });
		this.scope = textNode('select', { 'change': function() { self.updateControls(); } }, [ option('selected', _('Selected filtered domains')), option('all', _('All filtered domains')) ]);
		this.format = textNode('select', {}, [ option('txt', 'TXT'), option('csv', 'CSV') ]);
		this.copyButton = button(_('Copy'), function() { self.copyExport(); });
		this.downloadButton = button(_('Download'), function() { self.downloadExport(); });
		this.listSelect = textNode('select', { 'change': function() { self.updateControls(); } });
		this.addButton = button(_('Add selected domains to ruantiblock'), function() { self.confirmAdd(); }, 'cbi-button-action');
		this.ruantiInfo = textNode('p');
		this.flashWarning = textNode('p', { 'class': 'alert-message warning' }, _('Adding domains writes persistent files to router flash. Changes are not applied automatically. Use Update in the existing ruantiblock interface to apply them; Update may download lists and restart dnsmasq.'));
		this.ruantiLink = textNode('a', { 'href': L.url('admin', 'services', 'ruantiblock', 'service'),
			'class': 'cbi-button cbi-button-action' }, _('Open ruantiblock to apply changes'));

		var root = textNode('div', { 'class': 'dns-monitor' }, [
			textNode('style', {}, '.dns-monitor .dns-monitor-controls{display:flex;flex-wrap:wrap;gap:.6em;align-items:end;margin:.8em 0}.dns-monitor .dns-monitor-field{display:flex;flex-direction:column;gap:.25em;min-width:10em;max-width:100%}.dns-monitor .dns-monitor-field input,.dns-monitor .dns-monitor-field select{max-width:100%}.dns-monitor .dns-monitor-muted{opacity:.8}.dns-monitor .dns-monitor-scroll{overflow:auto;max-width:100%}.dns-monitor .dns-monitor-table td{overflow-wrap:anywhere;vertical-align:top}.dns-monitor .dns-monitor-table td:nth-child(3){min-width:12em}.dns-monitor [hidden]{display:none!important}@media(max-width:600px){.dns-monitor .dns-monitor-field{width:100%}.dns-monitor .dns-monitor-controls>*{max-width:100%}}'),
			textNode('h2', {}, _('DNS Monitor')),
			textNode('p', {}, _('Observe dnsmasq DNS requests for one client IP address. Only requests reaching this router are visible; cached answers on the client and encrypted or external DNS are not captured.')),
			textNode('p', { 'class': 'alert-message warning' }, _('Monitoring is shared globally by all browser sessions. Closing this page does not stop it. Enabling and disabling monitoring restarts dnsmasq and can briefly interrupt DNS service. The backend automatically stops monitoring at the session expiry.')),
			this.readonly ? textNode('p', { 'class': 'alert-message warning' }, _('Read-only access: monitoring controls and ruantiblock additions are unavailable.')) : textNode('span'),
			this.statusBox, this.errorBox,
			textNode('div', { 'class': 'dns-monitor-controls' }, [ field(_('Device'), this.device), field(_('Manual client IP'), this.manual), this.refreshClients ]),
			this.clientInfo, this.clientWarning,
			textNode('div', { 'class': 'dns-monitor-controls' }, [ this.startButton, this.stopButton, this.clearButton ]),
			textNode('h3', {}, _('Retained DNS history')),
			textNode('p', {}, _('Counts describe only retained requests matching the current filters, not lifetime totals. Domains are grouped by their exact case-insensitive name; parent domains are not combined.')),
			textNode('div', { 'class': 'dns-monitor-controls' }, [ field(_('Domain search'), this.search), field(_('Client filter'), this.filterClient),
				field(_('Record type filter'), this.filterType), field(_('Display'), this.mode), field(_('Sort'), this.sort) ]),
			this.summary,
			textNode('div', { 'class': 'dns-monitor-controls' }, [ this.selectFiltered, this.clearSelection, this.selectionSummary ]),
			textNode('div', { 'class': 'dns-monitor-scroll' }, this.table),
			textNode('div', { 'class': 'dns-monitor-controls' }, [ this.previous, this.pageLabel, this.next, field(_('Rows per page'), this.pageSelect) ]),
			textNode('div', { 'class': 'dns-monitor-controls' }, [ field(_('Export scope'), this.scope), field(_('Format'), this.format), this.copyButton, this.downloadButton ]),
			textNode('p', { 'class': 'dns-monitor-muted' }, _('Copy and download include all matching table pages. TXT contains one spelling of each domain; CSV contains every matching retained request.')),
			textNode('h3', {}, _('ruantiblock user lists')), this.ruantiInfo, this.flashWarning,
			textNode('div', { 'class': 'dns-monitor-controls' }, [ field(_('User list'), this.listSelect), this.addButton, this.ruantiLink ]),
			textNode('p', { 'class': 'dns-monitor-muted' }, _('Disabled lists are shown but cannot receive additions here. Select up to 500 valid domains per addition. Export remains available when ruantiblock is missing or unsupported.'))
		]);
		this.renderDevices();
		this.renderLists();
		if (data[0].status)
			this.acceptStatus(data[0].status);
		else
			this.pollError = _('Cannot contact DNS Monitor: %s').format(data[0].error);
		this.renderStatus();
		this.renderHistory();
		this.pollFn = function() { return self.tick(); };
		poll.add(this.pollFn, 2);
		/* Navigation removes only browser polling, never the shared backend session. */
		window.addEventListener('pagehide', function() { poll.remove(self.pollFn); }, { once: true });
		this.tick();
		return root;
	},

	acceptStatus: function(status) {
		checked(status);
		if (model.updateStatus(this.store, status)) {
			this.selected.clear();
			this.page = 0;
		}
		this.pruneSelection();
	},

	pruneSelection: function() {
		var retained = new Set(this.store.records.map(function(record) { return model.domainKey(record.domain); }));
		this.selected.forEach(function(key) { if (!retained.has(key)) this.selected.delete(key); }, this);
	},

	tick: function() {
		if (this.actionBusy || this.tickPromise)
			return this.tickPromise || Promise.resolve();
		var self = this, pages = 0;
		function fetchPage() {
			return callQueries(self.store.epoch, self.store.cursor, 500).then(checked).then(function(response) {
				if (!response.status || !Array.isArray(response.records))
					throw new Error(_('The service returned an invalid response.'));
				if (model.ingest(self.store, response)) {
					self.selected.clear();
					self.page = 0;
				}
				self.more = response.more;
				pages++;
				if (response.more && pages < 4 && !self.actionBusy)
					return fetchPage();
			});
		}
		this.tickPromise = fetchPage().then(function() {
			self.pollError = '';
			self.pruneSelection();
			if (Date.now() - self.lastClientRefresh > 30000)
				return self.refreshDevices();
		}).catch(function(error) {
			self.pollError = _('Cannot refresh DNS history: %s').format(message(error));
		}).then(function() {
			self.tickPromise = null;
			self.renderStatus();
			self.renderHistory();
		});
		return this.tickPromise;
	},

	renderDevices: function() {
		var selected = this.device.value;
		this.device.replaceChildren(option('', _('Enter an IP address manually')));
		var seen = new Set();
		(this.clients || []).forEach(function(client) {
			if (!client.ip || seen.has(client.ip)) return;
			seen.add(client.ip);
			var state = clientStates[client.status] || _('Connection status: %s').format(client.status || _('unknown'));
			this.device.appendChild(option(client.ip, [ client.hostname || _('Unknown hostname'), client.ip,
				client.mac || _('Unknown MAC'), state ].join(' \u2014 ')));
		}, this);
		this.device.value = seen.has(selected) ? selected : '';
		if (selected && !seen.has(selected)) this.manual.value = selected;
		this.clientInfo.textContent = this.clients === null ? _('Device discovery failed. Enter the client IP manually or refresh devices.') :
			_('%s discovered addresses.').format(seen.size);
		this.manual.disabled = this.readonly || !!this.device.value;
		this.updateControls();
	},

	refreshDevices: function() {
		var self = this;
		this.refreshClients.disabled = true;
		return callClients().then(checked).then(function(result) {
			self.clients = result.clients || [];
		}, function() { self.clients = null; }).then(function() {
			self.lastClientRefresh = Date.now();
			self.refreshClients.disabled = false;
			self.renderDevices();
		});
	},

	renderLists: function() {
		var integration = this.integration;
		this.listSelect.replaceChildren(option('', _('Choose a user list')));
		(integration.lists || []).forEach(function(list) {
			this.listSelect.appendChild(option(list.id, '%s (%s; %s; %s)'.format(list.name || list.id,
				list.enabled ? _('enabled') : _('disabled'), list.interface || '\u2014', list.mode || '\u2014'), !list.enabled));
		}, this);
		this.ruantiInfo.textContent = integration.available ? _('Add selected filtered domains to an enabled ruantiblock user list after confirmation.') :
			_('ruantiblock integration is unavailable: %s').format(integration.error || _('not installed or no supported user lists'));
		this.ruantiLink.hidden = !integration.available;
		this.updateControls();
	},

	updateControls: function() {
		var status = this.store.status, active = status && status.active, unavailable = !status || this.actionBusy;
		var client = this.device.value || this.manual.value.trim();
		this.startButton.disabled = this.readonly || unavailable || active || !client;
		this.stopButton.disabled = this.readonly || unavailable || !active;
		this.clearButton.disabled = this.readonly || unavailable;
		this.device.disabled = this.readonly || this.actionBusy || !!active;
		this.manual.disabled = this.readonly || this.actionBusy || !!active || !!this.device.value;
		var list = (this.integration.lists || []).find(function(item) { return item.id === this.listSelect.value; }, this);
		this.listSelect.disabled = this.readonly || this.actionBusy || !this.integration.available;
		var count = model.domains(this.filtered || [], this.selected).length;
		this.addButton.disabled = this.readonly || this.actionBusy || !this.integration.available || !list || !list.enabled || !count || count > 500;
		var available = this.scope.value === 'all' ? (this.filtered || []).length > 0 : count > 0;
		this.copyButton.disabled = !available;
		this.downloadButton.disabled = !available;
	},

	renderStatus: function() {
		var status = this.store.status;
		this.statusBox.replaceChildren();
		if (status) {
			this.statusBox.appendChild(textNode('p', {}, status.active ? _('Monitoring active for %s').format(status.client) : _('Monitoring stopped')));
			this.statusBox.appendChild(textNode('p', {}, _('Captured this session: %s. Retained on router: %s / %s. Automatic stop: %s.').format(
				status.captured, status.retained, status.max_records, status.active ? time(status.expires) : '\u2014')));
		}
		this.errorBox.hidden = !this.pollError && !(status && status.error);
		this.errorBox.textContent = this.pollError || (status && status.error) || '';
		this.updateControls();
	},

	resetPage: function() {
		this.page = 0;
		this.renderHistory();
	},

	refreshFilter: function(select, values, all) {
		var previous = select.value;
		select.replaceChildren(option('', all));
		Array.from(new Set(values)).sort().forEach(function(value) { select.appendChild(option(value, value)); });
		if (previous && !values.includes(previous)) select.appendChild(option(previous, previous));
		select.value = previous;
	},

	renderHistory: function() {
		var self = this;
		this.refreshFilter(this.filterClient, this.store.records.map(function(record) { return record.client_ip; }), _('All clients'));
		this.refreshFilter(this.filterType, this.store.records.map(function(record) { return record.record_type; }), _('All record types'));
		this.filtered = model.filterRecords(this.store.records, { search: this.search.value, client: this.filterClient.value, type: this.filterType.value });
		var rows = model.rows(this.filtered, this.mode.value === 'unique', this.sort.value);
		var pages = Math.max(1, Math.ceil(rows.length / this.pageSize));
		this.page = Math.max(0, Math.min(this.page, pages - 1));
		this.tableBody.replaceChildren();
		rows.slice(this.page * this.pageSize, (this.page + 1) * this.pageSize).forEach(function(row) {
			var checkbox = textNode('input', { 'type': 'checkbox', 'aria-label': _('Select domain %s').format(row.domain),
				'change': function() {
					if (checkbox.checked) self.selected.add(row.key); else self.selected.delete(row.key);
					self.renderHistory();
				} });
			checkbox.checked = self.selected.has(row.key);
			self.tableBody.appendChild(textNode('tr', { 'class': 'tr' }, [
				textNode('td', { 'class': 'td', 'data-title': _('Select') }, checkbox),
				textNode('td', { 'class': 'td', 'data-title': _('Time / last request') }, time(row.timestamp)),
				textNode('td', { 'class': 'td', 'data-title': _('Domain') }, row.domain),
				textNode('td', { 'class': 'td', 'data-title': _('Client IP') }, row.client_ip),
				textNode('td', { 'class': 'td', 'data-title': _('Record type') }, row.record_type),
				textNode('td', { 'class': 'td', 'data-title': _('Requests') }, String(row.count))
			]));
		});
		if (!rows.length) this.tableBody.appendChild(textNode('tr', { 'class': 'tr' }, textNode('td', { 'class': 'td', 'colspan': 6 }, _('No matching retained requests.'))));
		this.summary.textContent = _('%s matching requests; %s unique domains; %s requests loaded in this browser.').format(
			this.filtered.length, model.domains(this.filtered).length, this.store.records.length) +
			(this.more ? ' ' + _('Catching up with retained history (at most 2,000 records per poll).') : '');
		this.selectionSummary.textContent = _('%s selected filtered domains (%s selected in total).').format(model.domains(this.filtered, this.selected).length, this.selected.size);
		this.previous.disabled = this.page === 0;
		this.next.disabled = this.page >= pages - 1;
		this.pageLabel.textContent = _('Page %s of %s').format(this.page + 1, pages);
		this.updateControls();
	},

	confirm: function(title, paragraphs, label, action) {
		var self = this;
		ui.showModal(title, paragraphs.map(function(text) { return textNode('p', {}, text); }).concat([
			textNode('div', { 'class': 'right' }, [ button(_('Cancel'), function() { ui.hideModal(); }), ' ',
				button(label, function() { ui.hideModal(); self.runAction(action); }, 'cbi-button-action') ])
		]));
	},

	confirmMonitoring: function(start) {
		var client = (this.device.value || this.manual.value).trim();
		if (start && !validation.parseIPv4(client) && !validation.parseIPv6(client)) {
			ui.addNotification(null, textNode('p', {}, _('Enter a valid IPv4 or IPv6 address without a prefix or zone identifier.')), 'error');
			return;
		}
		var self = this;
		this.confirm(start ? _('Start monitoring?') : _('Stop monitoring?'), [
			_('This operation restarts dnsmasq and can briefly interrupt DNS resolution for all clients. It changes shared monitoring state for every browser session.'),
			start ? _('Capture DNS requests from %s? Starting a new session clears retained history.').format(client) : _('Disable query logging and restore the previous dnsmasq logging settings? Retained history remains available.')
		], start ? _('Start monitoring') : _('Stop monitoring'), function() {
			return (start ? callStart(client) : callStop()).then(function(status) { self.acceptStatus(status); });
		});
	},

	confirmClear: function() {
		var self = this;
		this.confirm(_('Clear retained history?'), [ _('This removes the shared retained history for all browser sessions. Active monitoring continues and no dnsmasq restart is needed.') ], _('Clear history'), function() {
			return callClear().then(function(status) { self.acceptStatus(status); });
		});
	},

	runAction: function(action) {
		if (this.actionBusy || this.readonly) return Promise.resolve();
		var self = this;
		this.actionBusy = true;
		this.updateControls();
		return Promise.resolve(this.tickPromise).then(action).catch(function(error) {
			ui.addNotification(null, textNode('p', {}, _('Operation failed: %s').format(message(error))), 'error');
		}).then(function() {
			self.actionBusy = false;
			self.renderStatus();
			self.renderHistory();
			return self.tick();
		});
	},

	exportSelection: function() {
		return this.scope.value === 'selected' ? this.selected : null;
	},

	copyExport: function() {
		var text = model.exportData(this.filtered, this.format.value, this.exportSelection());
		if (!navigator.clipboard || !navigator.clipboard.writeText) {
			this.copyFallback(text);
			return;
		}
		var self = this;
		navigator.clipboard.writeText(text).then(function() {
			ui.addNotification(null, textNode('p', {}, _('Filtered export copied to clipboard.')), 'info');
		}, function() { self.copyFallback(text); });
	},

	copyFallback: function(text) {
		var area = textNode('textarea', { 'readonly': true, 'rows': 12, 'style': 'width:100%' }, text);
		ui.showModal(_('Copy export'), [ textNode('p', {}, _('Clipboard access is unavailable. Select and copy the text below, or use Download.')),
			area, textNode('div', { 'class': 'right' }, button(_('Close'), function() { ui.hideModal(); })) ]);
		area.focus();
		area.select();
	},

	downloadExport: function() {
		var format = this.format.value, text = model.exportData(this.filtered, format, this.exportSelection());
		var url = URL.createObjectURL(new Blob([ text ], { type: format === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8' }));
		var anchor = textNode('a', { 'href': url, 'download': 'dns-monitor-' + new Date().toISOString().replace(/[:.]/g, '-') + '.' + format });
		try {
			document.body.appendChild(anchor);
			anchor.click();
		}
		finally {
			anchor.remove();
			window.setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
		}
	},

	confirmAdd: function() {
		var self = this, listId = this.listSelect.value;
		var list = (this.integration.lists || []).find(function(item) { return item.id === listId; });
		var selected = model.domains(this.filtered, this.selected);
		if (!list || !list.enabled || !selected.length || selected.length > 500 || this.readonly) return;
		/* Capture the confirmed set, not a moving live view during the RPC. */
		this.confirm(_('Persist domains to ruantiblock?'), [
			_('Add %s selected filtered domains to %s?').format(selected.length, list.name || list.id),
			_('This writes a persistent user list on router flash. Existing entries are preserved. Nothing is applied automatically; use Update in ruantiblock when ready. Update can download lists and restart dnsmasq.')
		], _('Add domains'), function() {
			/* Discover again: another administrator may have disabled the list. */
			return callLists().then(checked).then(function(integration) {
				self.integration = integration;
				self.renderLists();
				var current = (integration.lists || []).find(function(item) { return item.id === listId; });
				if (!integration.available || !current || !current.enabled)
					throw new Error(_('The selected list is no longer enabled or available.'));
				return callAdd(listId, selected.map(function(domain) { return model.domainKey(domain).replace(/\.$/, ''); })).then(checked);
			}).then(function(result) {
				var text = result.pending ?
					_('%s domains added; %s already present. Changes are pending: use Update in ruantiblock to apply them.') :
					_('%s domains added; %s already present. No new domains were written.');
				ui.addNotification(null, textNode('p', {}, text.format(result.added, result.duplicates)), 'info');
			});
		});
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
