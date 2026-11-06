// TLS herd web UI. Plain browser JavaScript, no build step.
//
// Every page is a server-rendered shell with an empty #view; the renderers
// below fill it from the same-origin JSON API (/api/v1). All dynamic text is
// inserted through DOM APIs (textContent), never innerHTML, so API data
// cannot inject markup. Mutating requests carry the CSRF token read from the
// tlsherd_csrf cookie (double submit, see internal/handler/middleware.go).
'use strict';

(function () {
  const API = '/api/v1';
  const IS_ADMIN = document.body.dataset.role === 'admin';
  const PAGE = document.body.dataset.page;
  const ID = (document.getElementById('app') || {dataset: {}}).dataset.id || '';

  // ---------------------------------------------------------------- core

  function cookie(name) {
    const prefix = name + '=';
    const c = document.cookie.split('; ').find((x) => x.startsWith(prefix));
    return c ? decodeURIComponent(c.slice(prefix.length)) : '';
  }

  class ApiError extends Error {
    constructor(status, body) {
      const e = body && body.error;
      super((e && e.message) || 'HTTP ' + status);
      this.status = status;
      this.code = (e && e.code) || '';
      this.details = e && e.details;
    }
  }

  // api performs a JSON API call. body may be a plain object (sent as JSON) or
  // FormData. It returns the decoded JSON, or null for empty responses.
  async function api(method, path, body, opts) {
    const headers = {Accept: 'application/json'};
    const init = {method, headers, credentials: 'same-origin'};
    if (method !== 'GET' && method !== 'HEAD') {
      headers['X-CSRF-Token'] = cookie('tlsherd_csrf');
    }
    if (body instanceof FormData) {
      init.body = body;
    } else if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(API + path, init);
    } catch (e) {
      throw new Error('network error: ' + e.message);
    }
    let data = null;
    const text = await res.text();
    if (text) {
      try { data = JSON.parse(text); } catch (e) { data = null; }
    }
    if (!res.ok) {
      if (res.status === 401 && !(opts && opts.noRedirect)) {
        location.href = '/login';
      }
      if (res.status === 403 && data && data.error && data.error.code === 'must_change_password'
          && !(opts && opts.noRedirect) && PAGE !== 'account' && PAGE !== 'login') {
        location.href = '/account';
      }
      throw new ApiError(res.status, data);
    }
    return data;
  }

  function errMsg(e) {
    if (e instanceof ApiError) {
      return e.message + (e.code ? ' (' + e.code + ')' : '');
    }
    return (e && e.message) || String(e);
  }

  // h builds a DOM element. Attributes: class, value, checked, on<event>, others as-is.
  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    let value;
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k === 'value') value = v;
      else if (k === 'checked') e.checked = true;
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? '' : v);
    }
    append(e, kids);
    if (value !== undefined) {
      e.value = value;
      // a select whose value matches no option would show nothing
      if (e.tagName === 'SELECT' && e.selectedIndex < 0) e.selectedIndex = 0;
    }
    return e;
  }

  function append(parent, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k === null || k === undefined || k === false) continue;
      parent.append(k instanceof Node ? k : document.createTextNode(String(k)));
    }
  }

  const link = (href, text) => h('a', {href}, text);
  const extLink = (href, text) => h('a', {href, target: '_blank', rel: 'noopener noreferrer'}, text);
  const code = (t) => h('code', null, t);
  const muted = (t) => h('span', {class: 'muted'}, t);
  const badge = (t, kind) => h('span', {class: 'badge' + (kind ? ' ' + kind : '')}, t);
  const btns = (...b) => h('div', {class: 'btns'}, b);

  // httpsEndpointLink builds an external https://host:port/ link for an endpoint.
  function httpsEndpointLink(host, port) {
    const label = host + ':' + port;
    return extLink('https://' + host + ':' + port + '/', label);
  }

  // normalizeEndpointHost appends domainFQDN when host lacks that suffix.
  function normalizeEndpointHost(host, domainFQDN) {
    host = String(host || '').trim().replace(/\.$/, '').toLowerCase();
    domainFQDN = String(domainFQDN || '').trim().replace(/\.$/, '').toLowerCase();
    if (!host) return '';
    if (!domainFQDN) return host;
    if (host === domainFQDN || host.endsWith('.' + domainFQDN)) return host;
    return host + '.' + domainFQDN;
  }

  function button(label, onclick, cls) {
    const b = h('button', {type: 'button', class: cls || ''}, label);
    b.addEventListener('click', () => onclick(b));
    return b;
  }

  function toast(msg, kind) {
    const box = document.getElementById('toasts');
    const t = h('div', {class: 'toast ' + (kind || ''), role: kind === 'error' ? 'alert' : 'status'}, msg);
    box.append(t);
    setTimeout(() => t.remove(), kind === 'error' ? 12000 : 5000);
    t.addEventListener('click', () => t.remove());
  }

  // act runs fn with btn disabled, toasts the outcome and reports success.
  async function act(btn, fn, okMsg) {
    if (btn) btn.disabled = true;
    try {
      await fn();
      if (okMsg) toast(okMsg, 'ok');
      return true;
    } catch (e) {
      toast(errMsg(e), 'error');
      return false;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // showSecret displays a value that the server reveals only once.
  function showSecret(title, secret, note) {
    const box = document.getElementById('secret');
    box.replaceChildren(h('div', {class: 'secretbox', role: 'alert'},
      h('strong', null, title),
      h('p', null, note),
      h('code', null, secret),
      button('Copy', async () => {
        try { await navigator.clipboard.writeText(secret); toast('Copied', 'ok'); } catch (e) { toast('Copy failed; select the text manually', 'error'); }
      }), ' ',
      button('I saved it, dismiss', () => box.replaceChildren())));
    window.scrollTo({top: 0});
  }

  function fmt(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return isNaN(d) ? String(ts) : d.toLocaleString();
  }

  function daysLeft(ts) {
    return Math.floor((new Date(ts).getTime() - Date.now()) / 86400000);
  }

  function expiryBadge(ts) {
    if (!ts) return muted('—');
    const d = daysLeft(ts);
    const kind = d < 0 ? 'bad' : d < 30 ? 'warn' : 'ok';
    return h('span', null, fmt(ts), ' ', badge(d < 0 ? 'expired' : d + ' d', kind));
  }

  const shortFp = (fp) => (fp || '').slice(0, 12);

  function statusBadge(s) {
    const kind = {active: 'ok', pending: 'warn', accepted: 'ok', rejected: 'bad', blocked_identity: 'bad', offline: 'warn', deleted: 'bad'}[s];
    return badge(s, kind);
  }

  function severityBadge(s) {
    return badge(s, {critical: 'bad', error: 'bad', warning: 'warn', warn: 'warn', info: 'info'}[s]);
  }

  function stat(n, l, kind, href) {
    const box = h('div', {class: 'stat' + (kind ? ' ' + kind : '')}, h('div', {class: 'n'}, n), h('div', {class: 'l'}, l));
    return href ? h('a', {href}, box) : box;
  }

  function table(headers, rows, empty) {
    if (!rows.length) return h('p', {class: 'muted'}, empty || 'Nothing to show.');
    return h('div', {class: 'tablewrap'}, h('table', null,
      h('thead', null, h('tr', null, headers.map((x) => h('th', null, x)))),
      h('tbody', null, rows.map((r) => h('tr', null, r.map((c) => h('td', null, c)))))));
  }

  const PAGE_SIZE_ALL = 1000;
  const PAGE_SIZE_OPTS = [['25', '25'], ['50', '50'], ['100', '100'], ['all', 'all']];

  function parsePageSize(v, def) {
    if (v === 'all' || Number(v) >= PAGE_SIZE_ALL) return PAGE_SIZE_ALL;
    const n = Number(v);
    return n > 0 ? n : (def || 25);
  }

  function pageSizeSelectValue(limit) {
    return limit >= PAGE_SIZE_ALL ? 'all' : String(limit);
  }

  // pagerBar: "On page" + Prev/Next, right-aligned in the panel header. Call update after load.
  // update(got) for server pages (next off when got < limit); update(got, total) for client slices.
  function pagerBar(state, onChange) {
    const sizeSel = select('on_page', PAGE_SIZE_OPTS, pageSizeSelectValue(state.limit));
    const prev = button('← Prev', () => {
      const step = state.limit >= PAGE_SIZE_ALL ? PAGE_SIZE_ALL : state.limit;
      state.offset = Math.max(0, state.offset - step);
      onChange();
    });
    const next = button('Next →', () => {
      state.offset += state.limit >= PAGE_SIZE_ALL ? PAGE_SIZE_ALL : state.limit;
      onChange();
    });
    sizeSel.addEventListener('change', () => {
      state.limit = parsePageSize(sizeSel.value, 25);
      state.offset = 0;
      onChange();
    });
    const bar = h('div', {class: 'pager'},
      h('label', {class: 'inline'}, 'On page ', sizeSel),
      prev, next);
    return {
      bar,
      update(got, total) {
        prev.disabled = state.offset === 0;
        if (state.limit >= PAGE_SIZE_ALL) {
          next.disabled = true;
        } else if (total != null) {
          next.disabled = state.offset + got >= total;
        } else {
          next.disabled = got < state.limit;
        }
      },
    };
  }

  // pageItems returns the current page of a full in-memory list and clamps offset.
  function pageItems(items, state) {
    const all = items || [];
    if (state.limit >= PAGE_SIZE_ALL) {
      state.offset = 0;
      return all;
    }
    if (!all.length) {
      state.offset = 0;
      return all;
    }
    if (state.offset >= all.length) {
      state.offset = Math.floor((all.length - 1) / state.limit) * state.limit;
    }
    return all.slice(state.offset, state.offset + state.limit);
  }

  // section builds a card; a kid with class "pager" is placed in the header row (right).
  function section(title, ...kids) {
    let headRight = null;
    const body = [];
    for (const k of kids.flat(Infinity)) {
      if (k === null || k === undefined || k === false) continue;
      if (!headRight && k instanceof Element && k.classList.contains('pager')) {
        headRight = k;
        continue;
      }
      body.push(k);
    }
    return h('section', {class: 'card'},
      h('div', {class: 'card-head'}, h('h2', null, title), headRight),
      body);
  }

  function field(label, input, help) {
    return h('label', null, label, input, help ? h('span', {class: 'help'}, help) : null);
  }

  function input(name, value, attrs) {
    return h('input', Object.assign({name, value: value === undefined || value === null ? '' : String(value)}, attrs || {}));
  }

  function select(name, options, value) {
    return h('select', {name, value},
      options.map((o) => (Array.isArray(o) ? h('option', {value: o[0]}, o[1]) : h('option', {value: o}, o))));
  }

  function checkbox(name, label, checked, value) {
    return h('label', {class: 'check'}, h('input', {type: 'checkbox', name, value: value || '', checked: !!checked}), label);
  }

  function json(v) { return JSON.stringify(v, null, 2); }

  // loadInto renders an async section; failures show inline instead of breaking the page.
  async function loadInto(container, fn) {
    try {
      container.replaceChildren(await fn());
    } catch (e) {
      container.replaceChildren(h('p', {class: 'error'}, errMsg(e)));
    }
  }

  const slot = () => h('div', null, h('p', {class: 'muted'}, 'Loading…'));

  const serverLabel = (s) => s.label || (s.display_name || (s.last_ip || s.id));

  async function serversById() {
    const list = (await api('GET', '/servers')) || [];
    return {list, map: new Map(list.map((s) => [s.id, s]))};
  }

  // checkboxList renders groups as checkboxes; values() returns the selected ids.
  function groupPicker(groups, selected) {
    const sel = new Set(selected || []);
    const boxes = groups.map((g) => ({id: g.id, el: checkbox('g', g.name, sel.has(g.id), g.id)}));
    const node = h('div', null, boxes.length ? boxes.map((b) => b.el) : muted('No groups available.'));
    return {node, values: () => boxes.filter((b) => b.el.querySelector('input').checked).map((b) => b.id)};
  }

  // ------------------------------------------------- timezone picker

  const TZ_FALLBACK = [
    'UTC', 'Europe/London', 'Europe/Berlin', 'Europe/Moscow', 'Europe/Istanbul',
    'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
    'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Singapore', 'Australia/Sydney', 'Pacific/Auckland',
  ];

  function listTimeZones() {
    try {
      if (typeof Intl !== 'undefined' && typeof Intl.supportedValuesOf === 'function') {
        return Intl.supportedValuesOf('timeZone');
      }
    } catch (e) { /* ignore */ }
    return TZ_FALLBACK.slice();
  }

  function tzOffsetLabel(name, at) {
    try {
      const parts = new Intl.DateTimeFormat('en-US', {
        timeZone: name, timeZoneName: 'shortOffset',
      }).formatToParts(at || new Date());
      const p = parts.find((x) => x.type === 'timeZoneName');
      let off = (p && p.value) || 'UTC';
      if (off === 'GMT') off = 'UTC+0';
      off = off.replace(/^GMT/, 'UTC');
      return name + ' (' + off + ')';
    } catch (e) {
      return name;
    }
  }

  // timezonePicker returns {node, value()} with searchable IANA list.
  function timezonePicker(current) {
    const zones = listTimeZones();
    const now = new Date();
    const options = zones.map((z) => ({z, label: tzOffsetLabel(z, now)}));
    options.sort((a, b) => a.label.localeCompare(b.label));
    let value = current || 'UTC';
    if (!zones.includes(value)) value = 'UTC';
    const input = h('input', {
      type: 'text', class: 'tz-input', autocomplete: 'off',
      placeholder: 'Search time zones…', value: tzOffsetLabel(value, now),
    });
    const list = h('div', {class: 'tz-list', hidden: true});
    const wrap = h('div', {class: 'tz-picker'}, input, list);

    function render(filter) {
      const q = (filter || '').toLowerCase().trim();
      list.replaceChildren();
      let n = 0;
      for (const o of options) {
        if (q && !o.label.toLowerCase().includes(q) && !o.z.toLowerCase().includes(q)) continue;
        const item = h('button', {type: 'button', class: 'tz-item' + (o.z === value ? ' active' : '')}, o.label);
        item.addEventListener('mousedown', (ev) => {
          ev.preventDefault();
          value = o.z;
          input.value = o.label;
          list.hidden = true;
        });
        list.append(item);
        if (++n >= 80) break;
      }
      list.hidden = n === 0;
    }

    input.addEventListener('focus', () => render(input.value));
    input.addEventListener('input', () => render(input.value));
    input.addEventListener('blur', () => {
      setTimeout(() => { list.hidden = true; input.value = tzOffsetLabel(value, now); }, 150);
    });

    return {node: wrap, value: () => value};
  }

  // ------------------------------------------------- agent config form

  const DAYS = [[1, 'Mon'], [2, 'Tue'], [3, 'Wed'], [4, 'Thu'], [5, 'Fri'], [6, 'Sat'], [7, 'Sun']];

  const CFG_FIELDS = [
    {group: 'Polling', fields: [
      {p: 'enroll_interval', l: 'Enroll interval', t: 'text', help: 'Go duration, e.g. 1m. How often a not-yet-accepted agent retries.'},
      {p: 'poll_interval', l: 'Poll interval', t: 'text', help: 'Go duration, e.g. 12h.'},
      {p: 'jitter', l: 'Jitter', t: 'number', help: 'Fraction 0..1 added to intervals.'},
    ]},
    {group: 'Maintenance window', fields: [
      {p: 'maintenance_window.tz', l: 'Time zone', t: 'tz', help: 'IANA time zone.'},
      {p: 'maintenance_window.days', l: 'Days', t: 'days'},
      {p: 'maintenance_window.from', l: 'From', t: 'text', help: 'HH:MM'},
      {p: 'maintenance_window.to', l: 'To', t: 'text', help: 'HH:MM'},
      {p: 'urgent_threshold', l: 'Urgent threshold', t: 'text', help: 'Apply outside the window when the installed certificate expires sooner than this.'},
      {p: 'stage_outside_window', l: 'Stage new certificates outside the window', t: 'bool'},
      {p: 'strict_cert_check', l: 'Validate certificate before install/reload', t: 'bool',
        help: 'When on, the agent refuses expired, not-yet-valid, or critically broken certs (no file update, no restart). Key mismatch always fails.'},
    ]},
    {group: 'Post-install TLS check', fields: [
      {p: 'post_check.enabled', l: 'Enabled', t: 'bool'},
      {p: 'post_check.addr', l: 'Address', t: 'text', help: 'host:port the agent dials after restart.'},
      {p: 'post_check.sni', l: 'SNI', t: 'text'},
    ]},
    {group: 'Backups', fields: [
      {p: 'backups.keep', l: 'Backups to keep', t: 'number'},
    ]},
  ];

  function getPath(o, path) {
    return path.split('.').reduce((a, k) => (a === undefined || a === null ? undefined : a[k]), o);
  }

  function setPath(o, path, v) {
    const keys = path.split('.');
    const last = keys.pop();
    let cur = o;
    for (const k of keys) {
      if (typeof cur[k] !== 'object' || cur[k] === null) cur[k] = {};
      cur = cur[k];
    }
    cur[last] = v;
  }

  // configForm renders every agentcfg.Config field. read() returns the edited document.
  function configForm(cfg) {
    const readers = [];
    const form = h('div', null);
    for (const g of CFG_FIELDS) {
      const fs = h('fieldset', null, h('legend', null, g.group));
      for (const f of g.fields) {
        const cur = getPath(cfg, f.p);
        let node;
        let read;
        switch (f.t) {
          case 'bool': {
            const c = h('input', {type: 'checkbox', checked: !!cur});
            node = h('label', {class: 'check'}, c, f.l);
            read = () => c.checked;
            break;
          }
          case 'number': {
            const i = h('input', {type: 'number', step: 'any', value: cur === undefined ? '' : cur});
            node = field(f.l, i, f.help);
            read = () => {
              if (i.value.trim() === '') return 0;
              const n = Number(i.value);
              if (!Number.isFinite(n)) throw new Error(f.l + ' must be a number');
              return n;
            };
            break;
          }
          case 'select': {
            const s = h('select', {value: cur || f.options[0]}, f.options.map((o) => h('option', {value: o}, o)));
            node = field(f.l, s, f.help);
            read = () => s.value;
            break;
          }
          case 'lines': {
            const t = h('textarea', {rows: 3}, '');
            t.value = (cur || []).join('\n');
            node = field(f.l, t, f.help);
            read = () => t.value.split('\n').map((x) => x.trim()).filter(Boolean);
            break;
          }
          case 'days': {
            const sel = new Set(cur || []);
            const boxes = DAYS.map(([n, name]) => [n, h('input', {type: 'checkbox', checked: sel.has(n)}), name]);
            node = h('div', null, h('strong', null, f.l), h('div', null, boxes.map(([, c, name]) => h('label', {class: 'check'}, c, name))));
            read = () => boxes.filter(([, c]) => c.checked).map(([n]) => n);
            break;
          }
          case 'tz': {
            const tz = timezonePicker(cur || 'UTC');
            node = field(f.l, tz.node, f.help);
            read = () => tz.value();
            break;
          }
          default: {
            const i = h('input', {value: cur === undefined || cur === null ? '' : String(cur)});
            node = field(f.l, i, f.help);
            read = () => i.value.trim();
          }
        }
        readers.push([f.p, read]);
        fs.append(node);
      }
      form.append(fs);
    }
    return {
      node: form,
      read() {
        const out = JSON.parse(JSON.stringify(cfg));
        for (const [p, r] of readers) setPath(out, p, r());
        return out;
      },
    };
  }

  // ------------------------------------------------------------- pages

  const pages = {};

  // ---- login

  pages.login = function () {
    const form = document.getElementById('login-form');
    const err = document.getElementById('login-error');
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.hidden = true;
      const btn = form.querySelector('button[type=submit]');
      btn.disabled = true;
      try {
        const res = await api('POST', '/auth/login', {login: form.login.value, password: form.password.value}, {noRedirect: true});
        location.href = (res && res.user && res.user.must_change_password) ? '/account' : '/';
      } catch (e) {
        err.textContent = e instanceof ApiError && e.status === 401 ? 'Invalid login or password.' : errMsg(e);
        err.hidden = false;
        btn.disabled = false;
      }
    });
  };

  // ---- dashboard

  pages.dashboard = async function (root) {
    const d = await api('GET', '/dashboard');
    const servers = d.servers || {};
    const open = d.open_events || {};
    const grid = h('div', {class: 'grid'},
      stat(d.domains, 'Domains', '', '/domains'),
      stat(d.domains_expired, 'Expired', d.domains_expired ? 'bad' : '', '/domains'),
      stat(d.domains_expiring_soon, 'Expiring soon', d.domains_expiring_soon ? 'warn' : '', '/domains'),
      IS_ADMIN ? stat(d.domains_ungrouped, 'Domains without group', d.domains_ungrouped ? 'warn' : '', '/domains') : null,
      Object.keys(servers).sort().map((k) => stat(servers[k], 'Servers: ' + k, k === 'blocked_identity' ? 'bad' : '', '/servers')),
      stat(d.pending_enrollments, 'Pending enrollments', d.pending_enrollments ? 'warn' : '', IS_ADMIN ? '/enrollments' : null),
      stat(d.identity_alerts, 'Identity alerts', d.identity_alerts ? 'bad' : '', IS_ADMIN ? '/enrollments' : null),
      stat(d.endpoints_down, 'Endpoints down', d.endpoints_down ? 'bad' : '', '/monitor'),
      Object.keys(open).sort().map((k) => stat(open[k], 'Open events: ' + k, k === 'critical' || k === 'error' ? 'bad' : '', '/events')));
    root.replaceChildren(grid);

    const expiring = d.expiring || [];
    root.append(section('Expiring certificates', table(
      ['Domain', 'Expires', 'Days left'],
      expiring.map((e) => [link('/domains/' + e.domain_id, e.fqdn), fmt(e.not_after), badge(e.days_left < 0 ? 'expired' : String(e.days_left), e.days_left < 0 ? 'bad' : 'warn')]),
      'No certificates expire soon.')));

    if (IS_ADMIN) {
      const s = slot();
      root.append(section('Pending enrollments', s, link('/enrollments', 'Open queue →')));
      loadInto(s, async () => {
        const list = (await api('GET', '/enrollments?status=pending')) || [];
        return table(['IP', 'Agent', 'Reason', 'Last seen'],
          list.slice(0, 8).map((e) => [e.remote_ip, e.client_name || '', reasonBadge(e.reason), fmt(e.last_seen_at)]),
          'No agents are waiting.');
      });
    }

    const ev = slot();
    root.append(section('Open events', ev, link('/events', 'All events →')));
    loadInto(ev, async () => {
      const list = (await api('GET', '/events?limit=10&unresolved=1')) || [];
      return eventsTable(list, () => location.reload());
    });
  };

  const REASONS = {
    first_seen: ['new agent', 'info'],
    identity_ip_changed: ['IP changed', 'bad'],
    identity_key_changed: ['key changed', 'bad'],
    re_enroll_after_delete: ['re-enroll after delete', 'warn'],
  };

  function reasonBadge(r) {
    const x = REASONS[r];
    return x ? badge(x[0], x[1]) : badge(r || '—');
  }

  function notifyStatusBadge(st) {
    if (!st || st === 'none') return muted('—');
    const kind = st === 'sent' ? 'ok' : (st === 'failed' ? 'bad' : (st === 'partial' || st === 'pending' ? 'warn' : ''));
    return badge(st, kind);
  }

  function notifyExpand(e) {
    const rows = e.notifications || [];
    const summary = notifyStatusBadge(e.notify_status);
    if (!rows.length) return summary;
    return h('details', {class: 'notify-details'},
      h('summary', null, summary),
      h('table', {class: 'nested'},
        h('thead', null, h('tr', null, h('th', null, 'Account'), h('th', null, 'Channel'), h('th', null, 'Kind'), h('th', null, 'Status'))),
        h('tbody', null, rows.map((n) => h('tr', null,
          h('td', null, n.account_name),
          h('td', null, code(n.channel)),
          h('td', null, n.kind),
          h('td', null, notifyStatusBadge(n.status), n.last_error ? h('div', {class: 'small muted'}, n.last_error) : null))))));
  }

  function eventsTable(list, onChange, maps) {
    const smap = (maps && maps.servers) || new Map();
    const dmap = (maps && maps.domains) || new Map();
    return table(['When', 'Severity', 'Type', 'Server', 'Domain', 'Message', 'Notify', 'Status', ''],
      list.map((e) => {
        const s = e.server_id ? smap.get(e.server_id) : null;
        const d = e.domain_id ? dmap.get(e.domain_id) : null;
        return [
          fmt(e.at), severityBadge(e.severity), code(e.type),
          s ? link('/servers/' + s.id, serverLabel(s)) : (e.server_id ? code(e.server_id.slice(0, 8)) : muted('—')),
          d ? link('/domains/' + d.id, d.fqdn) : (e.domain_id ? code(e.domain_id.slice(0, 8)) : muted('—')),
          h('div', null, e.message, detailsBlock(e.details)),
          notifyExpand(e),
          e.resolved_at ? badge('resolved ' + fmt(e.resolved_at), 'ok') : badge('open', 'warn'),
          e.resolved_at ? '' : button('Dismiss', async (b) => {
            if (await act(b, () => api('POST', '/events/' + e.id + '/dismiss'), 'Event dismissed')) {
              if (onChange) onChange();
            }
          }),
        ];
      }), 'No events.');
  }

  function detailsBlock(d) {
    if (!d || (typeof d === 'object' && Object.keys(d).length === 0)) return null;
    return h('details', null, h('summary', {class: 'small muted'}, 'details'), h('pre', null, json(d)));
  }

  // ---- enrollments

  pages.enrollments = async function (root) {
    let status = 'pending';
    const state = {limit: 25, offset: 0};
    const list = h('div', null);
    const filter = select('status', [['pending', 'Pending'], ['accepted', 'Accepted'], ['rejected', 'Rejected'], ['', 'All']], status);
    filter.addEventListener('change', () => { status = filter.value; state.offset = 0; refresh(); });
    const pager = pagerBar(state, () => refresh());
    root.replaceChildren(
      h('div', {class: 'toolbar'}, h('label', {class: 'inline'}, 'Show ', filter), button('Refresh', () => refresh())),
      section('Enrollments', pager.bar, list));

    async function refresh() {
      await loadInto(list, async () => {
        const [enrolls, servers] = await Promise.all([
          api('GET', '/enrollments' + (status ? '?status=' + encodeURIComponent(status) : '')),
          api('GET', '/servers'),
        ]);
        const all = enrolls || [];
        const page = pageItems(all, state);
        pager.update(page.length, all.length);
        const rows = page.map((e) => enrollRow(e, servers || []));
        return table(['IP', 'Agent', 'Reason', 'Keys', 'Last seen', 'Status', 'Decision'], rows,
          status === 'pending' ? 'No agents are waiting for approval.' : 'No enrollments.');
      });
    }

    function enrollRow(e, servers) {
      const pending = e.status === 'pending';
      const keys = h('div', {class: 'small'},
        e.presented_key_prefix ? h('div', null, 'presented: ', code(e.presented_key_prefix)) : null,
        e.previous_key_prefix ? h('div', null, 'previous: ', code(e.previous_key_prefix)) : null);
      let decision;
      if (pending) {
        const name = input('display_name', '', {placeholder: 'display name (optional)'});
        const opts = [['', '— create new server —']].concat(servers.map((s) => [s.id, serverLabel(s) + (s.key_prefix ? ' [' + s.key_prefix + ']' : '')]));
        const linkSel = select('link_server_id', opts, e.previous_server_id || '');
        const identity = e.reason === 'identity_ip_changed' || e.reason === 'identity_key_changed';
        decision = h('div', null,
          identity ? h('div', {class: 'small error'}, 'Identity change: accept only if you trust this host; it re-binds the existing server.') : null,
          name, linkSel,
          btns(
            button('Accept', async (b) => {
              const body = {};
              if (name.value.trim()) body.display_name = name.value.trim();
              if (linkSel.value) body.link_server_id = linkSel.value;
              if (identity && !confirm('Accept this identity change and re-bind the existing server to ' + e.remote_ip + '?')) return;
              let res;
              if (await act(b, async () => { res = await api('POST', '/enrollments/' + e.id + '/accept', body); }, 'Enrollment accepted')) {
                showSecret('Agent API key (' + res.key_prefix + ')', res.api_key,
                  'Shown once. The agent receives it automatically on its next enroll/poll; keep a copy only if you must configure it by hand.');
                refresh();
              }
            }, 'primary'),
            button('Reject', async (b) => {
              if (!confirm('Reject the enrollment from ' + e.remote_ip + '?')) return;
              if (await act(b, () => api('POST', '/enrollments/' + e.id + '/reject'), 'Enrollment rejected')) refresh();
            }, 'danger')));
      } else {
        decision = h('div', {class: 'small'}, e.decided_at ? fmt(e.decided_at) : '',
          e.server_id ? h('div', null, link('/servers/' + e.server_id, 'server')) : null);
      }
      return [e.remote_ip, e.client_name || '', reasonBadge(e.reason), keys, fmt(e.last_seen_at), statusBadge(e.status), decision];
    }

    await refresh();
  };

  // ---- groups

  pages.groups = async function (root) {
    const list = h('div', null);
    const form = h('form', {class: 'row'},
      field('Name', input('name', '', {required: true, maxlength: 128})),
      field('Description', input('description', '')),
      h('button', {type: 'submit', class: 'primary'}, 'Create group'));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const b = form.querySelector('button');
      if (await act(b, () => api('POST', '/groups', {name: form.elements.name.value, description: form.elements.description.value}), 'Group created')) {
        form.reset();
        refresh();
      }
    });
    root.replaceChildren(section('New group', form), section('Groups', list));

    async function refresh() {
      await loadInto(list, async () => {
        const groups = (await api('GET', '/groups')) || [];
        if (!groups.length) return h('p', {class: 'muted'}, 'No groups yet.');
        return h('div', null, groups.map(groupItem));
      });
    }

    function groupItem(g) {
      const body = h('div', null, h('p', {class: 'muted'}, 'Loading…'));
      const d = h('details', {class: 'item'}, h('summary', null, g.name, ' ', g.description ? muted('— ' + g.description) : null), body);
      let loaded = false;
      d.addEventListener('toggle', () => {
        if (!d.open || loaded) return;
        loaded = true;
        loadInto(body, () => groupBody(g, d));
      });
      return d;
    }

    async function groupBody(g, details) {
      const [perms, users] = await Promise.all([api('GET', '/groups/' + g.id + '/permissions'), api('GET', '/users')]);
      const byUser = new Map((perms || []).map((p) => [p.user_id, p]));
      const edit = h('form', {class: 'row'},
        field('Name', input('name', g.name, {required: true})),
        field('Description', input('description', g.description)),
        h('button', {type: 'submit'}, 'Save'),
        button('Delete group', async (b) => {
          if (!confirm('Delete group "' + g.name + '"? Domains must belong to another group first.')) return;
          if (await act(b, () => api('DELETE', '/groups/' + g.id), 'Group deleted')) refresh();
        }, 'danger'));
      edit.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        if (await act(edit.querySelector('button'), () => api('PATCH', '/groups/' + g.id, {name: edit.elements.name.value, description: edit.elements.description.value}), 'Group saved')) refresh();
      });

      const rows = [];
      const matrix = [];
      for (const u of users || []) {
        if (u.role === 'admin' || !u.is_active) continue; // admins implicitly have full access
        const p = byUser.get(u.id) || {};
        const r = checkbox('r', 'read', p.can_read);
        const c = checkbox('c', 'config', p.can_write_config);
        const w = checkbox('w', 'certs', p.can_write_certs);
        const [ri, ci, wi] = [r, c, w].map((x) => x.querySelector('input'));
        // write permissions imply read
        ci.addEventListener('change', () => { if (ci.checked) ri.checked = true; });
        wi.addEventListener('change', () => { if (wi.checked) ri.checked = true; });
        ri.addEventListener('change', () => { if (!ri.checked) { ci.checked = false; wi.checked = false; } });
        matrix.push({id: u.id, ri, ci, wi});
        rows.push([u.login, u.display_name, h('div', null, r, c, w)]);
      }
      const save = button('Save permissions', async (b) => {
        const permissions = matrix.filter((m) => m.ri.checked || m.ci.checked || m.wi.checked)
          .map((m) => ({user_id: m.id, can_read: m.ri.checked, can_write_config: m.ci.checked, can_write_certs: m.wi.checked}));
        await act(b, () => api('PUT', '/groups/' + g.id + '/permissions', {permissions}), 'Permissions saved');
      }, 'primary');
      return h('div', null, edit, h('h3', null, 'Operator permissions'),
        table(['Login', 'Name', 'Permissions'], rows, 'No active operators. Create one on the Users page.'),
        rows.length ? save : null,
        h('p', {class: 'help'}, 'Administrators always have full access. "config" = edit server configs and assignments, "certs" = upload and roll back certificates.'));
    }

    await refresh();
  };

  // ---- domains

  pages.domains = async function (root) {
    const state = {limit: 25, offset: 0};
    const list = h('div', null);
    const pager = pagerBar(state, () => refresh());
    const groups = (await api('GET', '/groups')) || [];
    const picker = groupPicker(groups, []);
    const form = h('form', null,
      h('div', {class: 'row'}, field('FQDN', input('fqdn', '', {required: true, placeholder: 'www.example.com'})), field('Notes', input('notes', ''))),
      h('h3', null, 'Groups (optional)'),
      h('p', {class: 'help'}, 'Groups control operator access only. You can create a domain with no group and assign groups later.'),
      picker.node,
      h('p', null, h('button', {type: 'submit', class: 'primary'}, 'Create domain')));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      let created;
      const ids = picker.values();
      if (await act(form.querySelector('button'), async () => {
        created = await api('POST', '/domains', {fqdn: form.fqdn.value, notes: form.notes.value, group_ids: ids});
      }, 'Domain created')) location.href = '/domains/' + created.id;
    });
    root.replaceChildren(section('Domains', pager.bar, list), section('New domain', form));

    async function refresh() {
      await loadInto(list, async () => {
        const domains = (await api('GET', '/domains')) || [];
        const gname = new Map(groups.map((g) => [g.id, g.name]));
        const page = pageItems(domains, state);
        pager.update(page.length, domains.length);
        const rows = page.map((d) => {
          const c = d.current_certificate;
          return [
            link('/domains/' + d.id, d.fqdn),
            c ? 'v' + d.current_version : muted('no certificate'),
            c ? expiryBadge(c.not_after) : '',
            (d.group_ids || []).map((id) => gname.get(id) || id.slice(0, 8)).join(', ') || badge('no group', 'warn'),
            d.notes || '',
          ];
        });
        return table(['Domain', 'Version', 'Expires', 'Groups', 'Notes'], rows, 'No domains yet.');
      });
    }
    await refresh();
  };

  // ---- domain detail

  pages.domain = async function (root) {
    const base = '/domains/' + ID;
    const parts = {head: slot(), upload: slot(), versions: slot(), assign: slot()};
    root.replaceChildren(parts.head, parts.upload, parts.versions, parts.assign);

    const reload = () => Promise.all([
      loadInto(parts.head, headSection),
      loadInto(parts.versions, versionsSection),
      loadInto(parts.assign, assignSection),
    ]);

    async function headSection() {
      const [d, groups] = await Promise.all([api('GET', base), api('GET', '/groups')]);
      document.querySelector('#app h1').textContent = d.fqdn;
      const c = d.current_certificate;
      const picker = groupPicker(groups || [], d.group_ids);
      const notes = h('textarea', {rows: 2, name: 'notes'}, '');
      notes.value = d.notes || '';
      const info = h('dl', {class: 'kv'},
        h('dt', null, 'Current version'), h('dd', null, c ? 'v' + d.current_version : 'none'),
        c ? [
          h('dt', null, 'Subject CN'), h('dd', null, c.subject_cn),
          h('dt', null, 'SANs'), h('dd', null, (c.sans || []).join(', ')),
          h('dt', null, 'Issuer'), h('dd', null, c.issuer_cn),
          h('dt', null, 'Valid until'), h('dd', null, expiryBadge(c.not_after)),
          h('dt', null, 'Fingerprint'), h('dd', null, code(c.fingerprint_sha256)),
          h('dt', null, 'Key'), h('dd', null, c.key_algo + ' ' + c.key_bits),
        ] : null);
      const save = button('Save notes & groups', async (b) => {
        const ids = picker.values();
        if (!ids.length) { toast('A domain needs at least one group', 'error'); return; }
        if (await act(b, () => api('PATCH', base, {notes: notes.value, group_ids: ids}), 'Domain saved')) reload();
      }, 'primary');
      const del = button('Delete domain', async (b) => {
        if (!confirm('Delete ' + d.fqdn + ' with all its versions and assignments? This cannot be undone.')) return;
        if (await act(b, () => api('DELETE', base), 'Domain deleted')) location.href = '/domains';
      }, 'danger');
      return section(d.fqdn, info, field('Notes', notes), h('h3', null, 'Groups'), picker.node, h('p', null, btns(save, del)));
    }

    // upload form is static: it must survive reloads of the other sections
    (function () {
      const form = h('form', null,
        h('div', {class: 'row'},
          field('Certificate (PEM)', h('input', {type: 'file', name: 'cert', required: true, accept: '.pem,.crt,.cer'})),
          field('Private key (PEM)', h('input', {type: 'file', name: 'key', required: true, accept: '.pem,.key'})),
          field('Chain (PEM, optional)', h('input', {type: 'file', name: 'chain', accept: '.pem,.crt,.cer'}))),
        h('p', {class: 'help'}, 'Each file up to 128 KiB, 1 MiB per request. The key must match. Expired, not-yet-valid, or domain-mismatch certificates need explicit confirmation.'),
        h('p', null, h('button', {type: 'submit', class: 'primary'}, 'Upload new version')));
      form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const fd = new FormData(form);
        if (!form.chain.files.length) fd.delete('chain');
        const b = form.querySelector('button');
        let res;
        const send = async () => { res = await api('POST', base + '/certificates', fd); };
        b.disabled = true;
        try {
          try {
            await send();
          } catch (e) {
            if (!(e instanceof ApiError) || (e.code !== 'confirmation_required' && e.code !== 'domain_mismatch')) throw e;
            const dt = e.details || {};
            const problems = dt.problems || [];
            let msg;
            if (problems.length) {
              msg = 'This certificate has issues that need confirmation:\n\n' +
                problems.map((p) => '• ' + (p.message || p.code)).join('\n') +
                '\n\nInstall it anyway?';
            } else {
              msg = 'The certificate does not cover ' + (dt.requested_domain || 'this domain') + '.\n' +
                'CN: ' + (dt.uploaded_cn || '—') + '\nSANs: ' + ((dt.uploaded_sans || []).join(', ') || '—') +
                '\n\nInstall it anyway?';
            }
            if (!confirm(msg)) return;
            fd.set('confirm_warnings', 'true');
            fd.set('confirm_domain_mismatch', 'true');
            fd.set('confirm_expired', 'true');
            fd.set('confirm_not_yet_valid', 'true');
            await send();
          }
          toast(res.unchanged ? 'Certificate already current; nothing changed' : 'Uploaded version ' + res.domain_certificate.version, 'ok');
          if (res.chain_warning) toast('Chain warning: ' + res.chain_warning, 'error');
          form.reset();
          reload();
        } catch (e) {
          toast(errMsg(e), 'error');
        } finally {
          b.disabled = false;
        }
      });
      parts.upload.replaceChildren(section('Upload certificate', form));
    })();

    async function versionsSection() {
      const vs = (await api('GET', base + '/certificates')) || [];
      const rows = vs.map((v) => {
        const c = v.certificate || {};
        const fp = c.fingerprint_sha256 || '';
        const dl = (part) => h('a', {href: API + '/certificates/' + fp + '/' + part}, part);
        return [
          'v' + v.version,
          v.is_current ? badge('current', 'ok') : '',
          h('span', {title: fp}, code(shortFp(fp))),
          c.subject_cn || '',
          expiryBadge(c.not_after),
          h('div', {class: 'small'}, fmt(v.activated_at), v.reason ? h('div', {class: 'muted'}, v.reason) : null),
          h('div', {class: 'small'}, dl('cert'), ' · ', dl('chain'), ' · ', dl('key')),
          v.is_current ? muted('current') : btns(
            button('Roll back', async (b) => {
              const reason = prompt('Reason for rolling back to v' + v.version + ' (optional):', '');
              if (reason === null) return;
              if (await act(b, () => api('POST', base + '/rollback', {version: v.version, reason}), 'Rolled back to v' + v.version)) reload();
            }),
            button('Delete', async (b) => {
              if (!confirm('Delete version v' + v.version + ' from this domain history? The current version cannot be deleted.')) return;
              if (await act(b, () => api('DELETE', base + '/certificates/' + v.version), 'Version deleted')) reload();
            }, 'danger')),
        ];
      });
      return section('Versions', table(['Version', '', 'Fingerprint', 'Subject CN', 'Expires', 'Activated', 'Download', ''], rows, 'No certificate uploaded yet.'),
        h('p', {class: 'help'}, 'Rollback re-activates an older version. Delete removes a non-current version from history (and unused certificate files).'));
    }

    async function assignSection() {
      const [assigns, srv] = await Promise.all([api('GET', base + '/servers'), serversById()]);
      const form = h('form', null);
      const sSel = select('server_id', srv.list.map((s) => [s.id, serverLabel(s)]), '');
      const mode = select('install_mode', [['', 'agent default'], ['symlink', 'symlink'], ['copy', 'copy']], '');
      const inputs = {
        cert_path: input('cert_path', '', {placeholder: 'leaf; relative to cert_root'}),
        key_path: input('key_path', ''),
        chain_path: input('chain_path', ''),
        fullchain_path: input('fullchain_path', '', {placeholder: 'leaf+chain; e.g. {domain}.crt'}),
      };
      const restart = h('textarea', {name: 'restart_override', rows: 3, placeholder: '{"type":"systemd","name":"nginx","reload_only":true}'}, '');
      form.append(
        h('div', {class: 'row'}, field('Server', sSel), field('Install mode', mode)),
        h('div', {class: 'row'},
          field('Certificate path (leaf)', inputs.cert_path),
          field('Key path', inputs.key_path),
          field('Chain path', inputs.chain_path),
          field('Fullchain path', inputs.fullchain_path)),
        field('Restart override (JSON, optional)', restart, 'Optional per-domain override of the agent local restart section. Prefer editing Agent local config on the server page.'),
        h('p', null, h('button', {type: 'submit', class: 'primary'}, 'Save assignment')));
      form.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        if (!sSel.value) { toast('Select a server', 'error'); return; }
        const body = {
          install_mode: mode.value,
          cert_path: inputs.cert_path.value.trim(),
          key_path: inputs.key_path.value.trim(),
          chain_path: inputs.chain_path.value.trim(),
          fullchain_path: inputs.fullchain_path.value.trim(),
        };
        if (restart.value.trim()) {
          try { body.restart_override = JSON.parse(restart.value); } catch (e) { toast('Restart override is not valid JSON', 'error'); return; }
        }
        if (await act(form.querySelector('button[type=submit]'), () => api('PUT', base + '/servers/' + sSel.value, body), 'Assignment saved')) reload();
      });
      const rows = (assigns || []).map((a) => {
        const s = srv.map.get(a.server_id);
        return [
          link('/servers/' + a.server_id, s ? serverLabel(s) : a.server_id),
          a.install_mode || muted('default'),
          a.cert_path || muted('default'), a.key_path || muted('default'),
          a.chain_path || muted('default'), a.fullchain_path || muted('default'),
          a.restart_override ? code(JSON.stringify(a.restart_override)) : muted('none'),
          btns(
            button('Edit', () => {
              sSel.value = a.server_id; mode.value = a.install_mode || '';
              inputs.cert_path.value = a.cert_path || ''; inputs.key_path.value = a.key_path || '';
              inputs.chain_path.value = a.chain_path || ''; inputs.fullchain_path.value = a.fullchain_path || '';
              restart.value = a.restart_override ? json(a.restart_override) : '';
              form.scrollIntoView({behavior: 'smooth'});
            }),
            button('Remove', async (b) => {
              if (!confirm('Stop deploying this domain to this server?')) return;
              if (await act(b, () => api('DELETE', base + '/servers/' + a.server_id), 'Assignment removed')) reload();
            }, 'danger')),
        ];
      });
      return section('Servers & paths',
        table(['Server', 'Mode', 'Cert', 'Key', 'Chain', 'Fullchain', 'Restart override', ''], rows, 'Not assigned to any server.'),
        h('h3', null, 'Assign / update'), form);
    }

    await reload();
  };

  // ---- servers

  function serverProblems(s) {
    const bits = [];
    if (s.agent_status === 'offline' || s.agent_status === 'blocked_identity') {
      bits.push(badge(s.agent_status, 'bad'));
    }
    (s.open_event_types || []).forEach((t) => bits.push(badge(t, s.max_event_severity === 'critical' ? 'bad' : 'warn')));
    if (s.endpoints_unhealthy) bits.push(badge(s.endpoints_unhealthy + ' endpoint' + (s.endpoints_unhealthy > 1 ? 's' : '') + ' down', 'bad'));
    if (s.local_config_conflict) bits.push(badge('local config conflict', 'warn'));
    if (!bits.length) return muted('ok');
    return h('div', null, bits.map((b, i) => [i ? ' ' : null, b]));
  }

  function endpointIssueBadge(issue) {
    if (!issue || issue === 'disabled') return issue === 'disabled' ? badge('disabled') : muted('ok');
    const kind = {unreachable: 'bad', tls_fail: 'bad', cert_expired: 'bad', cert_expiring: 'warn', not_checked: 'warn'}[issue] || 'warn';
    return badge(issue.replace(/_/g, ' '), kind);
  }

  function endpointsNestedTable(eps, dmap) {
    if (!eps.length) return h('p', {class: 'muted'}, 'No endpoints for this server.');
    return h('table', {class: 'nested'},
      h('thead', null, h('tr', null, h('th', null, 'Endpoint'), h('th', null, 'Domain'), h('th', null, 'Issue'))),
      h('tbody', null, eps.map((ep) => {
        const d = ep.domain_id && dmap ? dmap.get(ep.domain_id) : null;
        return h('tr', null,
          h('td', null, httpsEndpointLink(ep.host, ep.port)),
          h('td', null, d ? link('/domains/' + d.id, d.fqdn) : muted('—')),
          h('td', null, endpointIssueBadge(ep.issue)));
      })));
  }

  pages.servers = async function (root) {
    const state = {limit: 25, offset: 0};
    const list = h('div', null);
    const note = h('p', {class: 'muted'}, '');
    const pager = pagerBar(state, () => refresh());
    root.replaceChildren(section('Servers', pager.bar, note, list));

    async function refresh() {
      const [listRaw, eps, domains] = await Promise.all([
        api('GET', '/servers'), api('GET', '/monitor/endpoints'), api('GET', '/domains'),
      ]);
      const servers = listRaw || [];
      const dmap = new Map((domains || []).map((d) => [d.id, d]));
      const byServer = new Map();
      (eps || []).forEach((ep) => {
        if (!byServer.has(ep.server_id)) byServer.set(ep.server_id, []);
        byServer.get(ep.server_id).push(ep);
      });
      servers.sort((a, b) => {
        const score = (s) => (s.open_critical || 0) * 100 + (s.open_warning || 0) * 10 + (s.endpoints_unhealthy || 0) + (s.agent_status === 'offline' || s.agent_status === 'blocked_identity' ? 50 : 0);
        return score(b) - score(a) || serverLabel(a).localeCompare(serverLabel(b));
      });
      const problemCount = servers.filter((s) => (s.open_events || 0) > 0 || s.endpoints_unhealthy || s.agent_status === 'offline' || s.agent_status === 'blocked_identity').length;
      note.textContent = !servers.length
        ? 'No servers yet. Agents appear on the Enrollments page after their first contact.'
        : (problemCount ? problemCount + ' server(s) with problems (sorted first).' : 'No open agent/monitor problems.');

      const page = pageItems(servers, state);
      pager.update(page.length, servers.length);
      if (!servers.length) {
        list.replaceChildren();
        return;
      }
      list.replaceChildren(h('div', {class: 'tablewrap'}, h('table', null,
        h('thead', null, h('tr', null,
          h('th', null, ''), h('th', null, 'Server'), h('th', null, 'Agent'), h('th', null, 'Problems'),
          h('th', null, 'Last IP'), h('th', null, 'Last seen'), h('th', null, 'Domains'), h('th', null, 'Config'),
          h('th', null, 'Endpoints'))),
        h('tbody', null, page.flatMap((s) => {
          const related = byServer.get(s.id) || [];
          const toggle = h('button', {type: 'button', class: 'link expand-toggle', 'aria-expanded': 'false'}, related.length ? '▸' : '·');
          const main = h('tr', {class: 'server-row'},
            h('td', null, related.length ? toggle : muted('·')),
            h('td', null, link('/servers/' + s.id, serverLabel(s))),
            h('td', null, statusBadge(s.agent_status)),
            h('td', null, serverProblems(s)),
            h('td', null, s.last_ip || ''),
            h('td', null, fmt(s.last_seen_at)),
            h('td', null, String((s.domain_ids || []).length)),
            h('td', null, s.uses_custom_config ? badge('custom', 'info') : muted('defaults')),
            h('td', null, related.length ? badge(String(related.length), 'info') : muted('0')));
          const detail = h('tr', {class: 'server-endpoints', hidden: true},
            h('td', {colspan: 9}, endpointsNestedTable(related, dmap)));
          if (related.length) {
            toggle.addEventListener('click', () => {
              const open = detail.hidden;
              detail.hidden = !open;
              toggle.textContent = open ? '▾' : '▸';
              toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
          }
          return [main, detail];
        })))));
    }
    await refresh();
  };

  // ---- server detail

  pages.server = async function (root) {
    const base = '/servers/' + ID;
    const parts = {info: slot(), endpoints: slot(), local: slot(), config: slot()};
    root.replaceChildren(parts.info, parts.endpoints, parts.local, parts.config);
    const reload = () => Promise.all([
      loadInto(parts.info, infoSection),
      loadInto(parts.endpoints, endpointsSection),
      loadInto(parts.local, localConfigSection),
      loadInto(parts.config, configSection),
    ]);

    async function endpointsSection() {
      const [eps, domains] = await Promise.all([api('GET', '/monitor/endpoints'), api('GET', '/domains')]);
      const dmap = new Map((domains || []).map((d) => [d.id, d]));
      const mine = (eps || []).filter((ep) => ep.server_id === ID);
      return section('Endpoints',
        h('p', {class: 'muted'}, mine.length
          ? mine.length + ' endpoint(s). Checks dial this server\'s last IP with the host as SNI.'
          : 'No endpoints linked to this server. Add them on the Monitor page.'),
        endpointsNestedTable(mine, dmap),
        h('p', null, link('/monitor', 'Open Monitor →')));
    }

    async function infoSection() {
      const [s, domains] = await Promise.all([api('GET', base), api('GET', '/domains')]);
      document.querySelector('#app h1').textContent = serverLabel(s);
      const dmap = new Map((domains || []).map((d) => [d.id, d]));
      const info = h('dl', {class: 'kv'},
        h('dt', null, 'ID'), h('dd', null, code(s.id)),
        h('dt', null, 'Status'), h('dd', null, statusBadge(s.agent_status)),
        h('dt', null, 'Problems'), h('dd', null, serverProblems(s),
          s.open_events ? h('div', {class: 'small'}, link('/events?unresolved=1&server_id=' + s.id, s.open_events + ' open event(s) →')) : null),
        h('dt', null, 'Key prefix'), h('dd', null, s.key_prefix ? code(s.key_prefix) : '—'),
        h('dt', null, 'Last IP'), h('dd', null, s.last_ip || '—'),
        h('dt', null, 'Last seen'), h('dd', null, fmt(s.last_seen_at)),
        h('dt', null, 'First seen'), h('dd', null, fmt(s.created_at)),
        h('dt', null, 'Domains'), h('dd', null, (s.domain_ids || []).length
          ? (s.domain_ids).map((id) => [link('/domains/' + id, dmap.has(id) ? dmap.get(id).fqdn : id.slice(0, 8)), ' ']) : '—'));
      const name = input('display_name', s.display_name || '', {maxlength: 128, placeholder: s.last_ip || 'display name'});
      const rename = h('form', {class: 'row'}, field('Display name', name), h('button', {type: 'submit'}, 'Save name'));
      rename.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        if (await act(rename.querySelector('button'), () => api('PATCH', base, {display_name: name.value}), 'Name saved')) reload();
      });
      const rotate = button('Rotate agent key', async (b) => {
        if (!confirm('Issue a new agent key? The old key keeps working for 24 hours; the agent picks up the new key on its next poll.')) return;
        let res;
        if (await act(b, async () => { res = await api('POST', base + '/rotate-key'); }, 'Key rotated')) {
          showSecret('New agent key (' + res.key_prefix + ')', res.api_key,
            'Shown once. Delivered to the agent automatically; old keys expire ' + fmt(res.old_keys_expire_at) + '.');
          reload();
        }
      });
      const revoke = button('Revoke all keys', async (b) => {
        if (!confirm('Revoke ALL keys of this server now? The agent will have to re-enroll and be accepted again.')) return;
        if (await act(b, () => api('DELETE', base + '/keys'), 'Keys revoked')) reload();
      }, 'danger');
      const del = button('Delete server', async (b) => {
        if (!confirm('Delete this server? Its assignments are removed and the agent must re-enroll.')) return;
        if (await act(b, () => api('DELETE', base), 'Server deleted')) location.href = '/servers';
      }, 'danger');
      return section('Server', info, rename, h('h3', null, 'Agent key'), h('p', null, btns(rotate, revoke)), h('p', null, del));
    }

    async function localConfigSection() {
      const view = await api('GET', base + '/local-config');
      const services = (view.services || []).map((s) => [s.id, s.label || s.id]);
      const src = view.pending || view.reported || {service: 'custom', verify: {}, restart: {type: 'systemd'}, install: {}};
      const catalog = new Map((view.services || []).map((s) => [s.id, s]));
      const banners = [];
      if (view.conflict) {
        banners.push(h('div', {class: 'banner bad'},
          'Local config push conflict: the agent file changed since this edit. Re-save after reviewing the reported config.'));
      } else if (view.pending) {
        banners.push(h('div', {class: 'banner warn'},
          'Pending push revision ' + view.pending_revision + ' (base ' + shortFp(view.pending_base_hash || '') +
          '). The agent applies it on the next poll and keeps one previous file as agent.local.cfg.prev.'));
      }
      if (view.reported) {
        banners.push(h('p', null, 'Reported service ', badge(view.reported.service || 'custom', 'info'),
          ' · hash ', code(shortFp(view.reported_hash || '')),
          view.reported_updated_at ? ' · ' + fmt(view.reported_updated_at) : ''));
      } else {
        banners.push(h('p', {class: 'muted'}, 'Agent has not reported a local config yet.'));
      }

      const svcSel = select('service', services.length ? services : [['custom', 'Custom']], src.service || 'custom');
      const verifyCmd = h('textarea', {name: 'verify_command', rows: 3}, (src.verify && src.verify.command || []).join('\n'));
      const verifyTimeout = input('verify_timeout', (src.verify && src.verify.timeout) || '30s');
      const restartType = select('restart_type', ['systemd', 'docker', 'exec'], (src.restart && src.restart.type) || 'systemd');
      const restartName = input('restart_name', (src.restart && src.restart.name) || '');
      const reloadOnly = h('input', {type: 'checkbox', checked: !!(src.restart && src.restart.reload_only)});
      const restartCmd = h('textarea', {name: 'restart_command', rows: 3}, (src.restart && src.restart.command || []).join('\n'));
      const installMode = select('install_mode', ['symlink', 'copy'], (src.install && src.install.mode) || 'symlink');
      const certName = input('cert_name', (src.install && src.install.cert_name) || 'cert.pem');
      const keyName = input('key_name', (src.install && src.install.key_name) || 'key.pem');
      const chainName = input('chain_name', (src.install && src.install.chain_name) || 'chain.pem');
      const fullchainName = input('fullchain_name', (src.install && src.install.fullchain_name) || 'fullchain.pem');
      const certRoot = input('cert_root', src.cert_root || '', {placeholder: 'e.g. /cert (overrides TLSHERD_CERT_ROOT)'});
      const certPath = input('cert_path', src.cert_path || '', {placeholder: 'leaf; optional {domain}'});
      const keyPath = input('key_path', src.key_path || '');
      const chainPath = input('chain_path', src.chain_path || '');
      const fullchainPath = input('fullchain_path', src.fullchain_path || '', {placeholder: 'leaf+chain; e.g. {domain}.crt'});
      const strictCert = h('input', {type: 'checkbox', checked: src.strict_cert_check !== false});
      const confirmBox = h('input', {type: 'checkbox'});

      function applyCatalogDefaults(id) {
        const c = catalog.get(id);
        if (!c) return;
        verifyCmd.value = (c.verify && c.verify.command || []).join('\n');
        verifyTimeout.value = (c.verify && c.verify.timeout) || '30s';
        restartType.value = (c.restart && c.restart.type) || 'systemd';
        restartName.value = (c.restart && c.restart.name) || '';
        reloadOnly.checked = !!(c.restart && c.restart.reload_only);
        restartCmd.value = (c.restart && c.restart.command || []).join('\n');
      }
      svcSel.addEventListener('change', () => {
        if (confirm('Fill verify/restart from the ' + svcSel.value + ' catalog defaults?')) applyCatalogDefaults(svcSel.value);
      });

      function readLocal() {
        const lines = (t) => t.value.split('\n').map((x) => x.trim()).filter(Boolean);
        return {
          service: svcSel.value,
          verify: {command: lines(verifyCmd), timeout: verifyTimeout.value.trim() || '30s'},
          restart: {
            type: restartType.value,
            name: restartName.value.trim(),
            reload_only: reloadOnly.checked,
            command: lines(restartCmd),
          },
          install: {
            mode: installMode.value,
            cert_name: certName.value.trim() || 'cert.pem',
            key_name: keyName.value.trim() || 'key.pem',
            chain_name: chainName.value.trim() || 'chain.pem',
            fullchain_name: fullchainName.value.trim() || 'fullchain.pem',
            dir_mode: (src.install && src.install.dir_mode) || '0750',
            key_mode: (src.install && src.install.key_mode) || '0600',
            cert_mode: (src.install && src.install.cert_mode) || '0644',
            owner: (src.install && src.install.owner) || '',
            subdir: (src.install && src.install.subdir) || '',
          },
          cert_root: certRoot.value.trim(),
          cert_path: certPath.value.trim(),
          key_path: keyPath.value.trim(),
          chain_path: chainPath.value.trim(),
          fullchain_path: fullchainPath.value.trim(),
          strict_cert_check: strictCert.checked,
        };
      }

      const save = button('Save & push to agent', async (b) => {
        if (!confirmBox.checked) { toast('Confirm the local config push first.', 'error'); return; }
        const body = {config: readLocal(), confirm: true};
        if (await act(b, () => api('PUT', base + '/local-config', body), 'Local config queued for agent')) reload();
      }, 'primary');
      const resetAll = button('Reset all to service defaults', async (b) => {
        if (!confirmBox.checked) { toast('Confirm first.', 'error'); return; }
        if (!confirm('Reset verify and restart to catalog defaults for ' + svcSel.value + '?')) return;
        if (await act(b, () => api('PUT', base + '/local-config', {reset_all: true, service: svcSel.value, confirm: true}), 'Defaults queued')) reload();
      });

      return section('Agent local config (Edit)',
        ...banners,
        h('div', {class: 'banner warn'},
          'Agent-priority settings on the host ($TLSHERD_AGENT_DIR/agent.local.cfg, default /var/lib/tlsherd-agent/). Saving queues a push on the next poll; the agent keeps one previous version as .prev.'),
        h('fieldset', null, h('legend', null, 'Service'),
          field('Service type', svcSel, 'Selecting a service can fill catalog defaults for verify/restart.')),
        h('fieldset', null, h('legend', null, 'Pre-start check (verify)'),
          field('Command', verifyCmd, 'One argument per line, e.g. nginx then -t. Empty disables the check.'),
          field('Timeout', verifyTimeout)),
        h('fieldset', null, h('legend', null, 'Restart'),
          field('Type', restartType),
          field('Unit / container name', restartName),
          h('label', {class: 'check'}, reloadOnly, 'Reload instead of restart'),
          field('Command (exec / docker reload)', restartCmd, 'One argument per line.')),
        h('fieldset', null, h('legend', null, 'Install & paths'),
          field('Install mode', installMode),
          field('Filenames in versions/current', h('div', {class: 'row'}, certName, keyName, chainName, fullchainName),
            'fullchain.pem is leaf+intermediates (for nginx ssl_certificate).'),
          field('Cert root (working directory)', certRoot, 'Where the agent stores <fqdn>/versions and publishes extra paths. Default: TLSHERD_CERT_ROOT (/etc/tls).'),
          field('Extra publish paths', h('div', {class: 'row'}, certPath, keyPath, chainPath, fullchainPath),
            'Optional templates with {domain}. Must stay under cert_root. Use fullchain_path for nginx.'),
          h('label', {class: 'check'}, strictCert, 'Validate certificate before install/reload (overrides server schedule when set)')),
        h('p', null, h('label', {class: 'check'}, confirmBox, 'I confirm pushing this local config to the agent host')),
        h('p', null, btns(save, resetAll)));
    }

    async function configSection() {
      const eff = await api('GET', base + '/effective-config');
      const form = configForm(eff.config);
      const confirmBox = h('input', {type: 'checkbox', id: 'cfg-confirm'});
      const needConfirm = () => {
        if (confirmBox.checked) return true;
        toast('Tick the confirmation box first: this replaces the server configuration.', 'error');
        return false;
      };
      const save = button('Save schedule config', async (b) => {
        if (!needConfirm()) return;
        let cfg;
        try { cfg = form.read(); } catch (e) { toast(errMsg(e), 'error'); return; }
        if (await act(b, () => api('PUT', base + '/config', {config: cfg, confirm: true}), 'Config saved')) reload();
      }, 'primary');
      const force = button('Force from defaults', async (b) => {
        if (!needConfirm()) return;
        if (!confirm('Replace this server\'s schedule config with a copy of the current agent defaults?')) return;
        if (await act(b, () => api('PUT', base + '/config', {force_from_defaults: true, confirm: true}), 'Config reset from defaults')) reload();
      });
      return section('Schedule configuration (server-authoritative)',
        h('p', null, eff.uses_custom_config ? badge('custom config', 'info') : badge('using defaults', 'ok'),
          ' version ', eff.config_version, ' · hash ', code(shortFp(eff.config_hash))),
        h('p', {class: 'muted'}, 'Poll intervals, maintenance window, backups and post-check. Service verify/restart live in Agent local config above.'),
        form.node,
        h('p', null, h('label', {class: 'check'}, confirmBox, 'I confirm that I am replacing this server\'s schedule configuration')),
        h('p', null, btns(save, force)),
        h('details', null, h('summary', null, 'Effective schedule preview'), h('pre', null, json(eff.config))));
    }

    await reload();
  };

  // ---- agent defaults

  pages.defaults = async function (root) {
    const d = await api('GET', '/settings/agent-defaults');
    const form = configForm(d.config);
    const save = button('Save defaults', async (b) => {
      let cfg;
      try { cfg = form.read(); } catch (e) { toast(errMsg(e), 'error'); return; }
      if (!confirm('Update the agent defaults? All servers without a custom config adopt them on their next poll.')) return;
      if (await act(b, () => api('PUT', '/settings/agent-defaults', {config: cfg}), 'Defaults saved')) location.reload();
    }, 'primary');
    root.replaceChildren(section('Agent defaults',
      h('p', null, 'version ', d.config_version, ' · hash ', code(shortFp(d.config_hash)), ' · updated ', fmt(d.updated_at)),
      h('p', {class: 'muted'}, 'Schedule defaults (poll/window/backups/post-check). Per-agent service verify/restart are edited on the server page under Agent local config.'),
      form.node, h('p', null, save)));
  };

  // ---- events

  pages.events = async function (root) {
    const params = new URLSearchParams(location.search);
    const state = {
      type: params.get('type') || '',
      unresolved: params.get('unresolved') !== '0' && params.get('unresolved') !== 'false',
      limit: parsePageSize(params.get('limit') || '25', 25),
      offset: Number(params.get('offset') || 0) || 0,
      server_id: params.get('server_id') || '',
      domain_id: params.get('domain_id') || '',
    };
    const tableSlot = h('div', null);
    const [srv, domains] = await Promise.all([serversById(), api('GET', '/domains')]);
    const dmap = new Map((domains || []).map((d) => [d.id, d]));
    const types = ['', 'cert_expired', 'cert_expiring_soon', 'cert_key_mismatch', 'cert_chain_invalid', 'cert_domain_mismatch_confirmed',
      'cert_expired_upload_confirmed', 'cert_not_yet_valid_upload_confirmed',
      'cert_upload_rejected', 'cert_rollback_performed', 'agent_enroll_pending', 'agent_accepted', 'agent_rejected', 'agent_identity_mismatch',
      'agent_offline', 'agent_apply_failed', 'agent_verify_failed', 'agent_post_check_mismatch', 'agent_config_updated',
      'endpoint_down', 'endpoint_cert_mismatch', 'domain_ungrouped'];
    const typeSel = select('type', types.map((t) => [t, t || 'all types']), state.type);
    const serverSel = select('server_id', [['', 'all servers']].concat(srv.list.map((s) => [s.id, serverLabel(s)])), state.server_id);
    const domainSel = select('domain_id', [['', 'all domains']].concat((domains || []).map((d) => [d.id, d.fqdn])), state.domain_id);
    const unres = h('input', {type: 'checkbox', checked: state.unresolved});
    const applyFilters = () => {
      state.type = typeSel.value;
      state.unresolved = unres.checked;
      state.server_id = serverSel.value;
      state.domain_id = domainSel.value;
      state.offset = 0;
      refresh();
    };
    [typeSel, serverSel, domainSel, unres].forEach((x) => x.addEventListener('change', applyFilters));
    const filterBar = h('div', {class: 'toolbar'},
      h('label', {class: 'inline'}, 'Type ', typeSel),
      h('label', {class: 'inline'}, 'Server ', serverSel),
      h('label', {class: 'inline'}, 'Domain ', domainSel),
      h('label', {class: 'check'}, unres, 'open only'),
      button('Refresh', () => refresh()));

    const pager = pagerBar(state, () => refresh());
    root.replaceChildren(filterBar, section('Events', pager.bar, tableSlot));

    async function refresh() {
      const q = new URLSearchParams({limit: state.limit, offset: state.offset});
      if (state.type) q.set('type', state.type);
      if (state.unresolved) q.set('unresolved', '1');
      if (state.server_id) q.set('server_id', state.server_id);
      if (state.domain_id) q.set('domain_id', state.domain_id);
      await loadInto(tableSlot, async () => {
        const list = (await api('GET', '/events?' + q)) || [];
        pager.update(list.length);
        return eventsTable(list, refresh, {servers: srv.map, domains: dmap});
      });
    }

    if (IS_ADMIN) {
      const auditState = {limit: 25, offset: 0};
      const auditTable = h('div', null);
      const auditPager = pagerBar(auditState, () => refreshAudit());
      root.append(section('Audit log (admin)', auditPager.bar, auditTable));
      async function refreshAudit() {
        await loadInto(auditTable, async () => {
          const list = (await api('GET', '/audit?limit=' + auditState.limit + '&offset=' + auditState.offset)) || [];
          auditPager.update(list.length);
          return table(['When', 'Actor', 'Action', 'Entity', 'Details'],
            list.map((a) => {
              const actor = a.actor_display_name || a.actor_login
                || (a.actor_user_id ? code(a.actor_user_id.slice(0, 8)) : muted('system'));
              return [fmt(a.at), actor, code(a.action),
                a.entity_type + ' ' + a.entity_id, detailsBlock(a.details)];
            }), 'Audit log is empty.');
        });
      }
      await refreshAudit();
    }
    await refresh();
  };

  // ---- users

  pages.users = async function (root) {
    const state = {limit: 25, offset: 0};
    const list = h('div', null);
    const pager = pagerBar(state, () => refresh());
    const form = h('form', null,
      h('div', {class: 'row'},
        field('Login', input('login', '', {required: true, autocomplete: 'off'})),
        field('Display name', input('display_name', '')),
        field('Role', select('role', ['operator', 'admin'], 'operator')),
        field('Password', input('password', '', {type: 'password', required: true, minlength: 8, autocomplete: 'new-password', placeholder: 'min. 8 characters'}))),
      h('p', null, h('button', {type: 'submit', class: 'primary'}, 'Create user')));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const body = {login: form.login.value.trim(), display_name: form.display_name.value, password: form.password.value, role: form.role.value};
      if (await act(form.querySelector('button'), () => api('POST', '/users', body), 'User created')) { form.reset(); refresh(); }
    });
    root.replaceChildren(section('New user', form), section('Users', pager.bar, list));

    async function refresh() {
      await loadInto(list, async () => {
        const users = (await api('GET', '/users')) || [];
        const page = pageItems(users, state);
        pager.update(page.length, users.length);
        const meLogin = (document.body.dataset.login || '').toLowerCase();
        const rows = page.map((u) => {
          const role = select('role', ['operator', 'admin'], u.role);
          role.addEventListener('change', async () => {
            if (!(await act(role, () => api('PATCH', '/users/' + u.id, {role: role.value}), 'Role updated'))) role.value = u.role;
            refresh();
          });
          const isSelf = (u.login || '').toLowerCase() === meLogin;
          return [
            u.login, u.display_name, role,
            u.is_active ? badge('active', 'ok') : badge('disabled', 'bad'),
            fmt(u.last_login_at),
            btns(
              button('Rename', async (b) => {
                const n = prompt('Display name for ' + u.login + ':', u.display_name);
                if (n === null) return;
                if (await act(b, () => api('PATCH', '/users/' + u.id, {display_name: n}), 'Saved')) refresh();
              }),
              button(u.is_active ? 'Disable' : 'Enable', async (b) => {
                if (await act(b, () => api('PATCH', '/users/' + u.id, {is_active: !u.is_active}), 'Saved')) refresh();
              }),
              button(isSelf ? 'Change password' : 'Set password', () => {
                if (isSelf) {
                  location.href = '/account';
                  return;
                }
                location.href = '/account?set=' + encodeURIComponent(u.id);
              }),
              button('Delete', async (b) => {
                if (!confirm('Delete user ' + u.login + '?')) return;
                if (await act(b, () => api('DELETE', '/users/' + u.id), 'User deleted')) refresh();
              }, 'danger')),
          ];
        });
        return table(['Login', 'Name', 'Role', 'State', 'Last login', ''], rows, 'No users.');
      });
    }
    await refresh();
  };

  // ---- monitor

  pages.monitor = async function (root) {
    const state = {limit: 25, offset: 0};
    const summary = h('div', null);
    const filterBar = h('div', {class: 'toolbar'});
    const list = h('div', null);
    const results = h('div', null);
    const resultsSection = section('Results', results);
    resultsSection.hidden = true;
    const formSlot = h('div', null);
    const dnsSlot = h('div', {class: 'dns-rows'});
    const pager = pagerBar(state, () => refresh());
    root.replaceChildren(summary, filterBar, section('Endpoints', pager.bar, list), resultsSection,
      section('New endpoint', formSlot, dnsSlot));

    const [srv, domains] = await Promise.all([serversById(), api('GET', '/domains')]);
    const dmap = new Map((domains || []).map((d) => [d.id, d]));
    const domainOpts = (domains || []).map((d) => [d.id, d.fqdn]);
    const serverOpts = srv.list.map((s) => [s.id, serverLabel(s)]);

    const filterServer = select('filter_server', [['', 'all servers']].concat(serverOpts), '');
    const filterDomain = select('filter_domain', [['', 'all domains']].concat(domainOpts), '');
    filterBar.replaceChildren(
      h('label', {class: 'inline'}, 'Server ', filterServer),
      h('label', {class: 'inline'}, 'Domain ', filterDomain),
      button('Refresh', () => refresh()));
    [filterServer, filterDomain].forEach((x) => x.addEventListener('change', () => { state.offset = 0; refresh(); }));

    function makeEndpointRow(prefill) {
      const sSel = select('server_id', [['', '— select —']].concat(serverOpts), (prefill && prefill.server_id) || '');
      const dSel = select('domain_id', [['', '— select —']].concat(domainOpts), (prefill && prefill.domain_id) || '');
      const host = input('host', (prefill && prefill.host) || '', {required: true, placeholder: 'www or www.example.com'});
      const port = input('port', String((prefill && prefill.port) || 443), {type: 'number', min: 1, max: 65535, required: true});
      const addBtn = h('button', {type: 'button', class: 'primary'}, 'Add endpoint');
      const dnsBtn = h('button', {type: 'button'}, 'DNS check');
      const row = h('div', {class: 'row endpoint-add-row'},
        field('Server', sSel), field('Host', host), field('Domain', dSel), field('Port', port),
        h('div', {class: 'btns endpoint-add-actions'}, addBtn, dnsBtn));

      function resolvedHost() {
        const d = dmap.get(dSel.value);
        return normalizeEndpointHost(host.value, d ? d.fqdn : '');
      }

      function buildBody() {
        if (!sSel.value) { toast('Select a server', 'error'); return null; }
        if (!dSel.value) { toast('Select a domain', 'error'); return null; }
        const fqdn = resolvedHost();
        if (!fqdn) { toast('Enter a host', 'error'); return null; }
        return {
          server_id: sSel.value, domain_id: dSel.value, host: fqdn,
          port: Number(port.value) || 443, enabled: true,
        };
      }

      async function addOne(silent) {
        const body = buildBody();
        if (!body) return false;
        if (silent) {
          await api('POST', '/monitor/endpoints', body);
          return true;
        }
        return act(addBtn, () => api('POST', '/monitor/endpoints', body), 'Endpoint added');
      }

      addBtn.addEventListener('click', async () => {
        if (await addOne(false)) refresh();
      });
      dnsBtn.addEventListener('click', async () => {
        if (!dSel.value) { toast('Select a domain', 'error'); return; }
        const fqdn = resolvedHost();
        if (!fqdn) { toast('Enter a host', 'error'); return; }
        let res;
        if (!(await act(dnsBtn, async () => { res = await api('POST', '/monitor/dns-check', {host: fqdn}); }, 'DNS resolved'))) return;
        renderDNSRows(res, {domain_id: dSel.value, host: fqdn, port: Number(port.value) || 443});
      });
      return {row, sSel, dSel, host, port, addOne, addBtn};
    }

    const primary = makeEndpointRow();
    formSlot.append(primary.row);

    function renderDNSRows(res, base) {
      dnsSlot.replaceChildren();
      const records = (res && res.records) || [];
      if (!records.length) {
        dnsSlot.append(h('p', {class: 'muted'}, 'No A records for ' + (res.host || base.host)));
        return;
      }
      const matched = records.filter((r) => r.server_id);
      const unmatched = records.filter((r) => !r.server_id);
      const rowControls = [];

      if (matched.length) {
        const addAll = button('Add all', async (b) => {
          let ok = 0;
          const done = await act(b, async () => {
            for (const ctrl of rowControls) {
              try {
                if (await ctrl.addOne(true)) ok++;
              } catch (e) {
                toast(errMsg(e), 'error');
              }
            }
            if (!ok) throw new Error('No endpoints added');
          }, 'Added ' + matched.length + ' endpoint(s)');
          if (done) { dnsSlot.replaceChildren(); refresh(); }
        }, 'primary');
        dnsSlot.append(h('div', {class: 'toolbar'},
          h('span', {class: 'muted'}, matched.length + ' matching server(s) for ', code(res.host || base.host)),
          addAll));
      }

      for (const r of matched) {
        const ctrl = makeEndpointRow({
          server_id: r.server_id, domain_id: base.domain_id, host: base.host, port: base.port,
        });
        // DNS-suggested rows only need Add (no nested DNS check).
        const actions = ctrl.row.querySelector('.endpoint-add-actions');
        if (actions && actions.children[1]) actions.children[1].remove();
        rowControls.push(ctrl);
        dnsSlot.append(h('div', {class: 'dns-match'},
          h('div', {class: 'small muted'}, 'A ' + r.ip + (r.server_label ? ' · ' + r.server_label : '')),
          ctrl.row));
      }
      for (const r of unmatched) {
        dnsSlot.append(h('div', {class: 'row dns-ignored'},
          field('Server IP', input('ip', r.ip, {disabled: true})),
          h('span', {class: 'muted'}, 'not present on system (ignored)')));
      }
    }

    function issueBadge(issue) {
      if (!issue || issue === 'disabled') return issue === 'disabled' ? badge('disabled') : muted('ok');
      const kind = {unreachable: 'bad', tls_fail: 'bad', cert_expired: 'bad', cert_expiring: 'warn', not_checked: 'warn'}[issue] || 'warn';
      return badge(issue.replace(/_/g, ' '), kind);
    }

    async function showResults(ep) {
      resultsSection.hidden = false;
      resultsSection.querySelector('h2').textContent = 'Results: ' + ep.host + ':' + ep.port;
      await loadInto(results, async () => {
        const rs = (await api('GET', '/monitor/endpoints/' + ep.id + '/results?limit=50')) || [];
        return resultTable(rs);
      });
      resultsSection.scrollIntoView({behavior: 'smooth'});
    }

    function resultTable(rs) {
      return table(['Checked', 'IP', 'Reachable', 'TLS', 'Fingerprint', 'Expires', 'Issuer', 'Latency', 'Error'],
        rs.map((r) => [fmt(r.checked_at), r.connected_ip || muted('—'),
          r.reachable ? badge('yes', 'ok') : badge('no', 'bad'), r.tls_ok ? badge('ok', 'ok') : badge('fail', 'bad'),
          r.peer_fingerprint ? code(shortFp(r.peer_fingerprint)) : '', r.peer_not_after ? expiryBadge(r.peer_not_after) : '',
          r.issuer || '', r.latency_ms === null || r.latency_ms === undefined ? '' : r.latency_ms + ' ms', r.error || '']),
        'No results yet.');
    }

    async function refresh() {
      const eps = (await api('GET', '/monitor/endpoints')) || [];
      const fs = filterServer.value;
      const fd = filterDomain.value;
      const filtered = eps.filter((ep) => (!fs || ep.server_id === fs) && (!fd || ep.domain_id === fd));
      const counts = {total: filtered.length, unhealthy: 0, unreachable: 0, tls_fail: 0, cert_expired: 0, cert_expiring: 0, not_checked: 0};
      filtered.forEach((ep) => {
        if (!ep.healthy && ep.issue !== 'disabled') {
          counts.unhealthy++;
          if (counts[ep.issue] !== undefined) counts[ep.issue]++;
        }
      });
      summary.replaceChildren(section('Summary',
        h('div', {class: 'grid'},
          stat(counts.total, 'Endpoints', '', null),
          stat(counts.unhealthy, 'Unhealthy', counts.unhealthy ? 'bad' : '', null),
          stat(counts.unreachable, 'Unreachable', counts.unreachable ? 'bad' : '', null),
          stat(counts.tls_fail, 'TLS fail', counts.tls_fail ? 'bad' : '', null),
          stat(counts.cert_expired + counts.cert_expiring, 'Cert expiry', (counts.cert_expired || counts.cert_expiring) ? 'warn' : '', null),
          stat(counts.not_checked, 'Not checked', counts.not_checked ? 'warn' : '', null))));

      await loadInto(list, async () => {
        const page = pageItems(filtered, state);
        pager.update(page.length, filtered.length);
        const rows = page.map((ep) => {
          const s = srv.map.get(ep.server_id);
          const d = ep.domain_id ? dmap.get(ep.domain_id) : null;
          const l = ep.latest;
          return [
            httpsEndpointLink(ep.host, ep.port),
            s ? link('/servers/' + s.id, serverLabel(s)) : '',
            d ? link('/domains/' + d.id, d.fqdn) : muted('—'),
            issueBadge(ep.issue),
            l ? h('div', null,
              l.peer_not_after ? expiryBadge(l.peer_not_after) : '',
              l.peer_fingerprint ? h('div', {class: 'small'}, code(shortFp(l.peer_fingerprint))) : null,
              h('div', {class: 'small muted'},
                l.connected_ip ? l.connected_ip + ' · ' : '',
                fmt(l.checked_at), l.error ? ' · ' + l.error : '',
                l.latency_ms != null ? ' · ' + l.latency_ms + ' ms' : ''))
              : muted('—'),
            btns(
              button('Check now', async (b) => {
                if (await act(b, () => api('POST', '/monitor/endpoints/' + ep.id + '/check'), 'Check finished')) refresh();
              }),
              button('Results', () => showResults(ep)),
              button(ep.enabled ? 'Disable' : 'Enable', async (b) => {
                if (await act(b, () => api('PATCH', '/monitor/endpoints/' + ep.id, {enabled: !ep.enabled}), 'Saved')) refresh();
              }),
              button('Delete', async (b) => {
                if (!confirm('Delete endpoint ' + ep.host + ':' + ep.port + '?')) return;
                if (await act(b, () => api('DELETE', '/monitor/endpoints/' + ep.id), 'Endpoint deleted')) refresh();
              }, 'danger')),
          ];
        });
        return table(['Endpoint', 'Server', 'Domain', 'Issue', 'Latest', ''], rows, 'No endpoints. Add one below.');
      });
    }
    await refresh();
  };

  // ---- account

  pages.account = async function (root) {
    const me = await api('GET', '/auth/me');
    const self = me.user;
    const force = !!self.must_change_password;
    const setId = force ? '' : (new URLSearchParams(location.search).get('set') || '');
    let u = self;
    let adminSet = false;
    if (setId && setId !== self.id) {
      if (!IS_ADMIN) {
        toast('Administrators only', 'error');
        location.href = '/account';
        return;
      }
      try {
        u = await api('GET', '/users/' + setId);
        adminSet = true;
      } catch (e) {
        toast(errMsg(e), 'error');
        location.href = '/users';
        return;
      }
    }

    const kids = [];
    if (force) {
      kids.push(h('div', {class: 'banner warn'},
        'You must set a new password before using TLS herd. You will be signed out afterwards.'));
    } else if (adminSet) {
      kids.push(h('div', {class: 'banner warn'},
        'Setting a new password for ' + u.login + '. Their existing sessions will end.'));
    }
    const fields = [];
    if (!force && !adminSet) {
      fields.push(field('Current password', input('old_password', '', {type: 'password', required: true, autocomplete: 'current-password'})));
    }
    fields.push(
      field('New password', input('new_password', '', {type: 'password', required: true, minlength: 8, autocomplete: 'new-password'}), 'At least 8 characters.'),
      field('Confirm new password', input('new_password_confirm', '', {type: 'password', required: true, minlength: 8, autocomplete: 'new-password'})));
    fields.push(h('p', null,
      h('button', {type: 'submit', class: 'primary'}, adminSet || force ? 'Set password' : 'Change password'),
      adminSet ? [' ', h('a', {href: '/users', class: 'btn'}, 'Back to users')] : null));
    const form = h('form', null, ...fields);
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      if (form.new_password.value !== form.new_password_confirm.value) {
        toast('New passwords do not match.', 'error');
        return;
      }
      if (adminSet) {
        if (await act(form.querySelector('button'), () => api('POST', '/users/' + u.id + '/reset-password', {password: form.new_password.value}),
          'Password set; existing sessions ended')) {
          setTimeout(() => { location.href = '/users'; }, 800);
        }
        return;
      }
      const body = {new_password: form.new_password.value};
      if (!force) body.old_password = form.old_password.value;
      if (await act(form.querySelector('button'), () => api('POST', '/auth/password', body), 'Password changed')) {
        setTimeout(() => { location.href = '/login'; }, 800);
      }
    });
    kids.push(
      section('Profile', h('dl', {class: 'kv'},
        h('dt', null, 'Login'), h('dd', null, u.login),
        h('dt', null, 'Name'), h('dd', null, u.display_name || '—'),
        h('dt', null, 'Role'), h('dd', null, badge(u.role)),
        h('dt', null, 'Last login'), h('dd', null, fmt(u.last_login_at)))),
      section(force || adminSet ? 'Set a new password' : 'Change password', form));
    root.replaceChildren(...kids);
  };

  // ---- notification settings (admin)

  pages['notify-settings'] = async function (root) {
    if (!IS_ADMIN) { root.replaceChildren(h('p', {class: 'error'}, 'Admin only')); return; }
    const cfg = await api('GET', '/settings/notifications') || {};
    const smtp = cfg.smtp || {};
    const tg = cfg.telegram || {};
    const worker = cfg.worker || {};
    const host = h('input', {value: smtp.host || ''});
    const port = h('input', {type: 'number', value: smtp.port || 587});
    const user = h('input', {value: smtp.username || ''});
    const pass = h('input', {type: 'password', value: smtp.password || '', placeholder: 'unchanged if blank'});
    const from = h('input', {value: smtp.from || ''});
    const tls = select('tls', [['starttls', 'STARTTLS'], ['tls', 'TLS'], ['none', 'None']], smtp.tls || 'starttls');
    const bot = h('input', {type: 'password', value: tg.bot_token || '', placeholder: 'unchanged if blank'});
    const interval = h('input', {value: worker.interval || '15s'});
    const batch = h('input', {type: 'number', value: worker.batch || 50});
    const maxA = h('input', {type: 'number', value: worker.max_attempts || 8});

    const testChannel = select('ch', [['email', 'Email'], ['telegram', 'Telegram'], ['webhook', 'Webhook']], 'email');
    const testCfg = h('input', {placeholder: 'address / chat_id / url'});

    root.replaceChildren(
      section('SMTP', h('div', {class: 'row'},
        field('Host', host), field('Port', port), field('Username', user),
        field('Password', pass), field('From', from), field('TLS', tls))),
      section('Telegram', field('Bot token', bot)),
      section('Worker', h('div', {class: 'row'},
        field('Interval', interval), field('Batch', batch), field('Max attempts', maxA))),
      btns(button('Save', async (b) => {
        await act(b, () => api('PUT', '/settings/notifications', {
          smtp: {host: host.value.trim(), port: Number(port.value) || 587, username: user.value.trim(),
            password: pass.value, from: from.value.trim(), tls: tls.value},
          telegram: {bot_token: bot.value},
          worker: {interval: interval.value.trim() || '15s', batch: Number(batch.value) || 50,
            max_attempts: Number(maxA.value) || 8},
        }), 'Settings saved');
      }, 'primary')),
      section('Send test', h('div', {class: 'row'},
        field('Channel', testChannel), field('Target', testCfg),
        button('Send test', async (b) => {
          const ch = testChannel.value;
          let config = {};
          if (ch === 'email') config = {address: testCfg.value.trim()};
          else if (ch === 'telegram') config = {chat_id: testCfg.value.trim()};
          else config = {url: testCfg.value.trim()};
          await act(b, () => api('POST', '/settings/notifications/test', {channel: ch, config}), 'Test sent');
        }))),
      h('p', {class: 'muted'}, 'Manage recipients under ', link('/notification-accounts', 'Notification accounts'), '.'));
  };

  // ---- notification accounts (admin)

  pages['notify-accounts'] = async function (root) {
    if (!IS_ADMIN) { root.replaceChildren(h('p', {class: 'error'}, 'Admin only')); return; }
    const list = h('div', null);
    root.replaceChildren(
      h('div', {class: 'toolbar'},
        button('New account', () => { location.href = '/notification-accounts/new'; }, 'primary'),
        button('Refresh', () => refresh()),
        link('/settings/notifications', 'Channel settings →')),
      list);
    async function refresh() {
      await loadInto(list, async () => {
        const accounts = (await api('GET', '/notification-accounts')) || [];
        return table(['Name', 'Enabled', 'Allow all', 'Types', 'Timezone', ''],
          accounts.map((a) => [
            link('/notification-accounts/' + a.id, a.name),
            a.enabled ? badge('yes', 'ok') : badge('no', 'bad'),
            a.allow_all ? badge('all') : muted((a.scopes || []).length + ' scopes'),
            muted((a.event_types || []).length + ' types'),
            code(a.timezone || 'UTC'),
            button('Delete', async (b) => {
              if (!confirm('Delete notification account “' + a.name + '”?')) return;
              if (await act(b, () => api('DELETE', '/notification-accounts/' + a.id), 'Deleted')) refresh();
            }, 'danger'),
          ]), 'No notification accounts yet.');
      });
    }
    await refresh();
  };

  pages['notify-account-new'] = async function (root) {
    return pages['notify-account'](root);
  };

  pages['notify-account'] = async function (root) {
    if (!IS_ADMIN) { root.replaceChildren(h('p', {class: 'error'}, 'Admin only')); return; }
    const isNew = PAGE === 'notify-account-new' || !ID || ID === 'new';
    const [typesMeta, domains, groups, servers] = await Promise.all([
      api('GET', '/notification-event-types'),
      api('GET', '/domains'),
      api('GET', '/groups'),
      api('GET', '/servers'),
    ]);
    let acc = {
      name: '', enabled: true, allow_all: false,
      event_types: (typesMeta && typesMeta.defaults) || [],
      timezone: 'UTC', window_days: [1, 2, 3, 4, 5, 6, 7],
      window_from: '00:00', window_to: '24:00', scopes: [],
    };
    let dests = [];
    if (!isNew) {
      acc = await api('GET', '/notification-accounts/' + ID);
      dests = (await api('GET', '/notification-accounts/' + ID + '/destinations')) || [];
    }

    const name = h('input', {value: acc.name || ''});
    const enabled = h('input', {type: 'checkbox', checked: !!acc.enabled});
    const allowAll = h('input', {type: 'checkbox', checked: !!acc.allow_all});
    const tz = timezonePicker(acc.timezone || 'UTC');
    const from = h('input', {value: acc.window_from || '00:00'});
    const to = h('input', {value: acc.window_to || '24:00'});
    const daySel = new Set(acc.window_days || []);
    const dayBoxes = DAYS.map(([n, lab]) => [n, h('input', {type: 'checkbox', checked: daySel.has(n)}), lab]);

    const typeSet = new Set(acc.event_types || []);
    const allTypes = (typesMeta && typesMeta.types) || [];
    const typeBoxes = allTypes.map((t) => [t, h('input', {type: 'checkbox', checked: typeSet.has(t)})]);

    const scopeSel = new Set((acc.scopes || []).map((s) => s.kind + ':' + s.target_id));
    function scopeBox(kind, id, label) {
      const key = kind + ':' + id;
      const c = h('input', {type: 'checkbox', checked: scopeSel.has(key)});
      return {kind, id, c, el: h('label', {class: 'check'}, c, label)};
    }
    const domainScopes = (domains || []).map((d) => scopeBox('domain', d.id, d.fqdn));
    const groupScopes = (groups || []).map((g) => scopeBox('group', g.id, g.name));
    const serverScopes = (servers || []).map((s) => scopeBox('server', s.id, s.display_name || s.id));

    const destBox = h('div', null);

    function renderDests() {
      destBox.replaceChildren(
        table(['Channel', 'Config', 'Enabled', ''],
          dests.map((d) => {
            const cfg = d.config || {};
            const summary = d.channel === 'email' ? cfg.address
              : (d.channel === 'telegram' ? cfg.chat_id : cfg.url);
            return [
              code(d.channel), muted(summary || ''),
              d.enabled ? badge('yes', 'ok') : badge('no'),
              isNew ? '' : button('Remove', async (b) => {
                if (await act(b, () => api('DELETE', '/notification-accounts/' + ID + '/destinations/' + d.id), 'Removed')) {
                  dests = dests.filter((x) => x.id !== d.id);
                  renderDests();
                }
              }, 'danger'),
            ];
          }), 'No destinations yet.'),
        isNew ? muted('Save the account first, then add destinations.') : addDestForm());
    }

    function addDestForm() {
      const ch = select('ch', [['email', 'Email'], ['telegram', 'Telegram'], ['webhook', 'Webhook']], 'email');
      const val = h('input', {placeholder: 'address / chat_id / url'});
      const secret = h('input', {placeholder: 'webhook secret (optional)'});
      return h('div', {class: 'row'}, field('Channel', ch), field('Target', val), field('Secret', secret),
        button('Add destination', async (b) => {
          const channel = ch.value;
          let config = {};
          if (channel === 'email') config = {address: val.value.trim()};
          else if (channel === 'telegram') config = {chat_id: val.value.trim()};
          else config = {url: val.value.trim(), secret: secret.value.trim()};
          let created = null;
          if (await act(b, async () => {
            created = await api('POST', '/notification-accounts/' + ID + '/destinations',
              {channel, config, enabled: true});
          }, 'Destination added')) {
            dests.push(created);
            val.value = '';
            secret.value = '';
            renderDests();
          }
        }, 'primary'));
    }

    renderDests();

    async function save(b) {
      const body = {
        name: name.value.trim(),
        enabled: enabled.checked,
        allow_all: allowAll.checked,
        event_types: typeBoxes.filter(([, c]) => c.checked).map(([t]) => t),
        timezone: tz.value(),
        window_days: dayBoxes.filter(([, c]) => c.checked).map(([n]) => n),
        window_from: from.value.trim() || '00:00',
        window_to: to.value.trim() || '24:00',
        scopes: []
          .concat(domainScopes.filter((s) => s.c.checked).map((s) => ({kind: s.kind, target_id: s.id})))
          .concat(groupScopes.filter((s) => s.c.checked).map((s) => ({kind: s.kind, target_id: s.id})))
          .concat(serverScopes.filter((s) => s.c.checked).map((s) => ({kind: s.kind, target_id: s.id}))),
      };
      if (isNew) {
        let created = null;
        if (await act(b, async () => {
          created = await api('POST', '/notification-accounts', body);
        }, 'Account created')) {
          if (created && created.id) location.href = '/notification-accounts/' + created.id;
        }
      } else {
        if (await act(b, () => api('PUT', '/notification-accounts/' + ID, body), 'Saved')) {
          location.reload();
        }
      }
    }

    root.replaceChildren(
      h('p', null, link('/notification-accounts', '← All accounts')),
      section(isNew ? 'New notification account' : 'Edit notification account',
        h('div', null,
          field('Name', name),
          h('label', {class: 'check'}, enabled, 'Enabled'),
          h('label', {class: 'check'}, allowAll, 'Allow all (still filtered by event type)'),
          field('Timezone', tz.node),
          h('div', null, h('strong', null, 'Working days'),
            h('div', null, dayBoxes.map(([, c, lab]) => h('label', {class: 'check'}, c, lab)))),
          h('div', {class: 'row'}, field('From', from), field('To', to)),
          h('div', null,
            h('div', {class: 'row', style: 'align-items:center;gap:8px'},
              h('strong', null, 'Event types'),
              button('Select all', () => { typeBoxes.forEach(([, c]) => { c.checked = true; }); }),
              button('Deselect all', () => { typeBoxes.forEach(([, c]) => { c.checked = false; }); })),
            h('div', {class: 'checks'}, typeBoxes.map(([t, c]) => h('label', {class: 'check'}, c, code(t))))),
          h('div', null, h('strong', null, 'Scopes'),
            h('p', {class: 'muted small'}, 'Ignored when Allow all is on.'),
            h('h3', null, 'Domains'), h('div', null, domainScopes.map((s) => s.el)),
            h('h3', null, 'Groups'), h('div', null, groupScopes.map((s) => s.el)),
            h('h3', null, 'Servers'), h('div', null, serverScopes.map((s) => s.el))),
          btns(button('Save', save, 'primary'),
            isNew ? null : button('Delete', async (b) => {
              if (!confirm('Delete this account?')) return;
              if (await act(b, () => api('DELETE', '/notification-accounts/' + ID), 'Deleted')) {
                location.href = '/notification-accounts';
              }
            }, 'danger')))),
      section('Destinations', destBox));
  };

  // -------------------------------------------------------------- nav

  const NAV_COLLAPSE_KEY = 'tlsherd.nav.collapsed';

  function initNav() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;

    const collapseBtn = document.getElementById('nav-collapse');
    const menuBtn = document.getElementById('nav-menu');
    const backdrop = document.getElementById('nav-backdrop');

    function collapsedPref() {
      const v = localStorage.getItem(NAV_COLLAPSE_KEY);
      if (v === null) return true; // first visit: collapsed
      return v === '1';
    }
    function apply() {
      const isCollapsed = collapsedPref();
      document.body.classList.toggle('nav-collapsed', isCollapsed);
      if (collapseBtn) {
        collapseBtn.setAttribute('aria-label', isCollapsed ? 'Expand sidebar' : 'Collapse sidebar');
        collapseBtn.title = isCollapsed ? 'Expand' : 'Collapse';
      }
    }
    function setOpen(open) {
      document.body.classList.toggle('nav-open', open);
      if (menuBtn) menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (backdrop) backdrop.hidden = !open;
    }

    apply();
    setOpen(false);

    if (collapseBtn) {
      collapseBtn.addEventListener('click', () => {
        localStorage.setItem(NAV_COLLAPSE_KEY, collapsedPref() ? '0' : '1');
        apply();
      });
    }
    if (menuBtn) {
      menuBtn.addEventListener('click', () => {
        setOpen(!document.body.classList.contains('nav-open'));
      });
    }
    if (backdrop) {
      backdrop.addEventListener('click', () => setOpen(false));
    }
    document.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') setOpen(false);
    });
    sidebar.querySelectorAll('a.nav-link').forEach((a) => {
      a.addEventListener('click', () => setOpen(false));
    });
  }

  // -------------------------------------------------------------- boot

  document.body.addEventListener('htmx:configRequest', (ev) => {
    ev.detail.headers['X-CSRF-Token'] = cookie('tlsherd_csrf');
  });
  document.body.addEventListener('htmx:afterRequest', (ev) => {
    if (ev.detail.elt && ev.detail.elt.id === 'logout') location.href = '/login';
  });

  async function boot() {
    initNav();
    const run = pages[PAGE];
    if (!run) return;
    const root = document.getElementById('view');
    try {
      await run(root);
    } catch (e) {
      if (root) root.replaceChildren(h('p', {class: 'error'}, errMsg(e)));
    }
  }

  boot();
})();
