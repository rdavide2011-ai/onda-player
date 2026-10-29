/* Onda Player — client per Spotify Premium (Web API + Web Playback SDK)
 * Nessun backend: login OAuth PKCE, tutto salvato in localStorage.
 */

// ======================================================================
// Storage (localStorage con prefisso e try/catch)
// ======================================================================
const PREFIX = 'onda:';
const store = {
  get(key, fallback = null) {
    try {
      const raw = localStorage.getItem(PREFIX + key);
      return raw === null ? fallback : JSON.parse(raw);
    } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(PREFIX + key, JSON.stringify(value)); } catch { /* quota / privato */ }
  },
  remove(key) { try { localStorage.removeItem(PREFIX + key); } catch {} },
  clearAll() {
    try { Object.keys(localStorage).filter(k => k.startsWith(PREFIX)).forEach(k => localStorage.removeItem(k)); } catch {}
  },
  exportAll() {
    const out = {};
    try {
      Object.keys(localStorage).filter(k => k.startsWith(PREFIX)).forEach(k => {
        const key = k.slice(PREFIX.length);
        if (key === 'auth' || key === 'pkce') return; // mai esportare i token
        out[key] = JSON.parse(localStorage.getItem(k));
      });
    } catch {}
    return out;
  },
};

// ======================================================================
// Utilità
// ======================================================================
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s = '') => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = ms => {
  if (!Number.isFinite(ms) || ms < 0) ms = 0;
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
};
const img = (images, size = 300) => {
  if (!images || !images.length) return '';
  const sorted = [...images].sort((a, b) => (a.width || 0) - (b.width || 0));
  return (sorted.find(i => (i.width || 640) >= size) || sorted[sorted.length - 1]).url;
};
const artistsOf = item => (item?.artists || []).map(a => a.name).join(', ');
const sleep = ms => new Promise(r => setTimeout(r, ms));

function toast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' err' : '');
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), isError ? 5500 : 3000);
}

function coverHtml(url, name, cls = 'cover') {
  return url
    ? `<img class="${cls}" src="${esc(url)}" alt="" loading="lazy" />`
    : `<div class="${cls} cover-fallback" aria-hidden="true">${esc((name || '?').trim().charAt(0).toUpperCase())}</div>`;
}

// ======================================================================
// Configurazione
// ======================================================================
const SCOPES = [
  'streaming',
  'user-read-email',
  'user-read-private',
  'user-read-playback-state',
  'user-modify-playback-state',
  'user-read-currently-playing',
  'playlist-read-private',
  'playlist-read-collaborative',
  'user-library-read',
].join(' ');

const REDIRECT_URI = (location.origin + location.pathname).replace(/index\.html$/, '');
const API = 'https://api.spotify.com/v1';

// ======================================================================
// Auth — Authorization Code con PKCE (nessun client secret)
// ======================================================================
const auth = {
  get clientId() { return store.get('clientId', ''); },
  get data() { return store.get('auth', null); },
  isLoggedIn() { return !!this.data?.refresh_token; },

  async login() {
    const verifier = randomString(64);
    const challenge = await sha256b64url(verifier);
    const state = randomString(16);
    store.set('pkce', { verifier, state });
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      scope: SCOPES,
      code_challenge_method: 'S256',
      code_challenge: challenge,
      redirect_uri: REDIRECT_URI,
      state,
    });
    location.href = 'https://accounts.spotify.com/authorize?' + params;
  },

  // Gestisce il ritorno da Spotify (?code=...). Ritorna true se ha completato il login.
  async handleCallback() {
    const q = new URLSearchParams(location.search);
    if (!q.has('code') && !q.has('error')) return false;
    const pkce = store.get('pkce');
    history.replaceState(null, '', REDIRECT_URI + location.hash);
    if (q.get('error')) throw new Error(q.get('error') === 'access_denied' ? 'Accesso annullato.' : 'Errore Spotify: ' + q.get('error'));
    if (!pkce || q.get('state') !== pkce.state) throw new Error('Sessione di login non valida, riprova.');
    const tok = await tokenRequest({
      grant_type: 'authorization_code',
      code: q.get('code'),
      redirect_uri: REDIRECT_URI,
      client_id: this.clientId,
      code_verifier: pkce.verifier,
    });
    store.remove('pkce');
    this.save(tok);
    return true;
  },

  save(tok) {
    const prev = this.data || {};
    store.set('auth', {
      access_token: tok.access_token,
      refresh_token: tok.refresh_token || prev.refresh_token,
      expires_at: Date.now() + (tok.expires_in - 60) * 1000,
    });
  },

  _refreshing: null,
  async refresh() {
    if (this._refreshing) return this._refreshing;
    this._refreshing = (async () => {
      try {
        const tok = await tokenRequest({
          grant_type: 'refresh_token',
          refresh_token: this.data.refresh_token,
          client_id: this.clientId,
        });
        this.save(tok);
      } finally { this._refreshing = null; }
    })();
    return this._refreshing;
  },

  async token() {
    const d = this.data;
    if (!d) throw new Error('Non autenticato');
    if (Date.now() >= d.expires_at) await this.refresh();
    return this.data.access_token;
  },

  logout() { store.remove('auth'); store.remove('me'); },
};

async function tokenRequest(body) {
  const res = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (json.error === 'invalid_grant') { auth.logout(); }
    throw new Error(json.error_description || json.error || 'Errore token (' + res.status + ')');
  }
  return json;
}

function randomString(len) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const vals = crypto.getRandomValues(new Uint8Array(len));
  return [...vals].map(v => chars[v % chars.length]).join('');
}
async function sha256b64url(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ======================================================================
// Web API client
// ======================================================================
class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(path, { method = 'GET', body, query, retry = true } = {}) {
  const url = new URL(path.startsWith('http') ? path : API + path);
  if (query) Object.entries(query).forEach(([k, v]) => v !== undefined && v !== null && url.searchParams.set(k, v));
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: 'Bearer ' + await auth.token(),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && retry) { await auth.refresh(); return api(path, { method, body, query, retry: false }); }
  if (res.status === 429 && retry) {
    const wait = Math.min(10, Number(res.headers.get('Retry-After')) || 2);
    await sleep(wait * 1000);
    return api(path, { method, body, query, retry: false });
  }
  if (res.status === 204 || res.status === 202) return null;
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  if (!res.ok) {
    const reason = json?.error?.reason;
    let msg = json?.error?.message || `Errore ${res.status}`;
    if (reason === 'PREMIUM_REQUIRED') msg = 'Serve Spotify Premium per questa funzione.';
    if (reason === 'NO_ACTIVE_DEVICE') msg = 'Nessun dispositivo attivo. Apri Spotify o attendi che Onda sia pronta.';
    throw new ApiError(res.status, msg);
  }
  return json;
}

// Legge tutte le pagine di un endpoint paginato (con un tetto di sicurezza)
async function apiAll(path, query = {}, max = 500) {
  let out = [];
  let next = null;
  let first = await api(path, { query: { limit: 50, ...query } });
  out = out.concat(first.items || []);
  next = first.next;
  while (next && out.length < max) {
    const page = await api(next);
    out = out.concat(page.items || []);
    next = page.next;
  }
  return { ...first, items: out };
}

// ======================================================================
// Link Spotify → { type, id, uri }
// ======================================================================
function parseSpotifyLink(input) {
  const s = (input || '').trim();
  if (!s) return null;
  let m = s.match(/^spotify:(playlist|album|track|artist|show|episode):([A-Za-z0-9]{10,})$/);
  if (m) return { type: m[1], id: m[2], uri: s };
  m = s.match(/open\.spotify\.com\/(?:intl-[a-z]{2}(?:-[A-Za-z]{2})?\/)?(?:embed\/)?(playlist|album|track|artist|show|episode)\/([A-Za-z0-9]{10,})/);
  if (m) return { type: m[1], id: m[2], uri: `spotify:${m[1]}:${m[2]}` };
  if (/spotify\.link|spotify\.app\.link/.test(s)) return { short: true };
  return null;
}

// ======================================================================
// Libreria locale: salvati, recenti, cronologia brani
// ======================================================================
const lib = {
  saved() { return store.get('saved', []); },
  isSaved(uri) { return this.saved().some(x => x.uri === uri); },
  toggleSaved(entry) {
    let list = this.saved();
    if (list.some(x => x.uri === entry.uri)) {
      list = list.filter(x => x.uri !== entry.uri);
      store.set('saved', list);
      return false;
    }
    list.unshift({ ...entry, savedAt: Date.now() });
    store.set('saved', list.slice(0, 200));
    return true;
  },
  recent() { return store.get('recent', []); },
  addRecent(entry) {
    if (!entry?.uri) return;
    const list = this.recent().filter(x => x.uri !== entry.uri);
    list.unshift({ ...entry, at: Date.now() });
    store.set('recent', list.slice(0, 30));
  },
  history() { return store.get('history', []); },
  addHistory(track) {
    if (!track?.uri) return;
    const list = this.history();
    if (list[0]?.uri === track.uri) return;
    list.unshift({ ...track, at: Date.now() });
    store.set('history', list.slice(0, 100));
  },
  cache: {
    get(key, maxAgeMs) {
      const c = store.get('cache:' + key);
      return c && Date.now() - c.t < maxAgeMs ? c.v : null;
    },
    set(key, v) { store.set('cache:' + key, { t: Date.now(), v }); },
  },
};

// ======================================================================
// Player: Web Playback SDK (questo browser) + Spotify Connect (altri dispositivi)
// ======================================================================
const player = {
  sdk: null,
  deviceId: null,       // id del player nel browser
  sdkReady: false,
  sdkError: null,
  state: null,          // stato normalizzato
  stateAt: 0,           // timestamp dell'ultimo aggiornamento di stato
  activeDeviceId: null,
  activeDeviceName: '',
  pollTimer: null,
  seeking: false,

  init() {
    if (window.Spotify) return this._create();
    window.onSpotifyWebPlaybackSDKReady = () => this._create();
    const s = document.createElement('script');
    s.src = 'https://sdk.scdn.co/spotify-player.js';
    s.async = true;
    s.onerror = () => { this.sdkError = 'Impossibile caricare il player Spotify.'; };
    document.head.appendChild(s);
    this.startPolling();
  },

  _create() {
    if (this.sdk) return;
    this.sdk = new window.Spotify.Player({
      name: 'Onda Player (' + deviceLabel() + ')',
      getOAuthToken: cb => auth.token().then(cb).catch(() => {}),
      volume: store.get('volume', 70) / 100,
    });
    this.sdk.addListener('ready', ({ device_id }) => {
      this.deviceId = device_id;
      this.sdkReady = true;
      ui.renderDevicePill();
    });
    this.sdk.addListener('not_ready', () => { this.sdkReady = false; });
    this.sdk.addListener('player_state_changed', s => { if (s) this.applySdkState(s); });
    this.sdk.addListener('initialization_error', ({ message }) => { this.sdkError = 'Il browser non supporta la riproduzione: usa l\'app Spotify come dispositivo. (' + message + ')'; });
    this.sdk.addListener('authentication_error', () => { this.sdkError = 'Errore di autenticazione del player.'; toast('Sessione scaduta, rifai l\'accesso.', true); });
    this.sdk.addListener('account_error', () => { this.sdkError = 'Questo account non è Premium: la riproduzione nel browser non è disponibile.'; toast(this.sdkError, true); });
    this.sdk.addListener('playback_error', ({ message }) => toast('Errore di riproduzione: ' + message, true));
    this.sdk.addListener('autoplay_failed', () => toast('Tocca ▶ per avviare l\'audio.'));
    this.sdk.connect();
  },

  startPolling() {
    clearInterval(this.pollTimer);
    const tick = () => { if (document.visibilityState === 'visible') this.refreshState(); };
    tick();
    this.pollTimer = setInterval(tick, 5000);
  },

  async refreshState() {
    try {
      const s = await api('/me/player', { query: { additional_types: 'episode' } });
      if (!s) { if (!this.isLocal()) this.setState(null); return; }
      this.activeDeviceId = s.device?.id || null;
      this.activeDeviceName = s.device?.name || '';
      // Se sta suonando nel browser, lo stato dell'SDK è più preciso: non sovrascrivere
      if (this.isLocal() && this.state) { ui.renderDevicePill(); return; }
      const it = s.item;
      this.setState({
        uri: it?.uri,
        name: it?.name || '',
        artists: artistsOf(it) || it?.show?.name || '',
        album: it?.album?.name || '',
        image: img(it?.album?.images || it?.images, 300),
        imageLarge: img(it?.album?.images || it?.images, 640),
        duration: it?.duration_ms || 0,
        position: s.progress_ms || 0,
        playing: !!s.is_playing,
        shuffle: !!s.shuffle_state,
        repeat: s.repeat_state || 'off',
        contextUri: s.context?.uri || null,
      });
    } catch (e) {
      if (e.status === 403) return; // es. account non Premium: lo segnaliamo solo quando si prova a suonare
    }
  },

  applySdkState(s) {
    const t = s.track_window?.current_track;
    this.activeDeviceId = this.deviceId;
    this.activeDeviceName = 'Questo dispositivo';
    this.setState({
      uri: t?.uri,
      name: t?.name || '',
      artists: (t?.artists || []).map(a => a.name).join(', '),
      album: t?.album?.name || '',
      image: img(t?.album?.images, 300),
      imageLarge: img(t?.album?.images, 640),
      duration: s.duration || t?.duration_ms || 0,
      position: s.position || 0,
      playing: !s.paused,
      shuffle: !!s.shuffle,
      repeat: ['off', 'context', 'track'][s.repeat_mode] || 'off',
      contextUri: s.context?.uri || null,
    });
  },

  setState(st) {
    const prevUri = this.state?.uri;
    this.state = st;
    this.stateAt = performance.now();
    if (st?.uri && st.uri !== prevUri) {
      lib.addHistory({ uri: st.uri, name: st.name, artists: st.artists, image: st.image });
    }
    ui.renderPlayer();
  },

  position() {
    if (!this.state) return 0;
    const p = this.state.position + (this.state.playing ? performance.now() - this.stateAt : 0);
    return Math.min(p, this.state.duration || p);
  },

  isLocal() { return !!this.deviceId && this.activeDeviceId === this.deviceId; },

  // Sblocca l'audio su iOS/Safari: va chiamato dentro il gesto dell'utente
  unlock() { try { this.sdk?.activateElement?.(); } catch {} },

  // Avvia la riproduzione di un contesto (playlist/album/artista) o di brani
  async play({ contextUri, uris, offsetUri, offsetIndex, meta } = {}) {
    this.unlock();
    const body = {};
    if (contextUri) body.context_uri = contextUri;
    if (uris) body.uris = uris;
    if (offsetUri) body.offset = { uri: offsetUri };
    else if (Number.isInteger(offsetIndex)) body.offset = { position: offsetIndex };

    const target = await this.pickDevice();
    if (!target) {
      toast(this.sdkError || 'Nessun dispositivo disponibile. Apri l\'app Spotify e riprova.', true);
      ui.openDevices();
      return;
    }
    try {
      try {
        await api('/me/player/play', { method: 'PUT', query: { device_id: target }, body });
      } catch (e) {
        // il dispositivo attivo potrebbe essere andato offline: riprova nel browser
        if (e.status === 404 && this.sdkReady && target !== this.deviceId) {
          await api('/me/player/play', { method: 'PUT', query: { device_id: this.deviceId }, body });
        } else throw e;
      }
      if (meta) lib.addRecent(meta);
      setTimeout(() => this.refreshState(), 700);
    } catch (e) {
      toast(e.message, true);
    }
  },

  // Dispositivo su cui suonare: quello attivo, altrimenti il browser, altrimenti il primo disponibile
  async pickDevice() {
    if (this.activeDeviceId) return this.activeDeviceId;
    if (this.sdkReady && this.deviceId) return this.deviceId;
    // l'SDK può impiegare qualche secondo
    for (let i = 0; i < 6 && !this.sdkReady && !this.sdkError; i++) await sleep(500);
    if (this.sdkReady && this.deviceId) return this.deviceId;
    try {
      const { devices } = await api('/me/player/devices');
      return devices?.[0]?.id || null;
    } catch { return null; }
  },

  async toggle() {
    this.unlock();
    if (!this.state) {
      const last = lib.recent()[0];
      if (last) return this.play({ contextUri: last.type === 'track' ? undefined : last.uri, uris: last.type === 'track' ? [last.uri] : undefined, meta: last });
      return toast('Scegli prima qualcosa da ascoltare.');
    }
    const wasPlaying = this.state.playing;
    this.optimistic({ playing: !wasPlaying, position: this.position() });
    try {
      if (this.isLocal() && this.sdk) await this.sdk.togglePlay();
      else await api('/me/player/' + (wasPlaying ? 'pause' : 'play'), { method: 'PUT', query: { device_id: this.activeDeviceId || undefined } });
    } catch (e) { toast(e.message, true); this.refreshState(); }
  },

  async next() {
    try {
      if (this.isLocal() && this.sdk) await this.sdk.nextTrack();
      else await api('/me/player/next', { method: 'POST' });
      setTimeout(() => this.refreshState(), 600);
    } catch (e) { toast(e.message, true); }
  },

  async prev() {
    try {
      if (this.isLocal() && this.sdk) await this.sdk.previousTrack();
      else await api('/me/player/previous', { method: 'POST' });
      setTimeout(() => this.refreshState(), 600);
    } catch (e) { toast(e.message, true); }
  },

  async seek(ms) {
    this.optimistic({ position: ms });
    try {
      if (this.isLocal() && this.sdk) await this.sdk.seek(ms);
      else await api('/me/player/seek', { method: 'PUT', query: { position_ms: Math.round(ms) } });
    } catch (e) { toast(e.message, true); }
  },

  _volTimer: null,
  setVolume(pct) {
    store.set('volume', pct);
    clearTimeout(this._volTimer);
    this._volTimer = setTimeout(async () => {
      try {
        if (this.isLocal() && this.sdk) await this.sdk.setVolume(pct / 100);
        else if (this.activeDeviceId) await api('/me/player/volume', { method: 'PUT', query: { volume_percent: pct } });
      } catch (e) {
        if (e.status === 403) toast('Questo dispositivo non permette di cambiare il volume da remoto.');
      }
    }, 150);
  },

  async toggleShuffle() {
    if (!this.state) return;
    const v = !this.state.shuffle;
    this.optimistic({ shuffle: v });
    try { await api('/me/player/shuffle', { method: 'PUT', query: { state: v } }); }
    catch (e) { toast(e.message, true); this.refreshState(); }
  },

  async cycleRepeat() {
    if (!this.state) return;
    const order = ['off', 'context', 'track'];
    const v = order[(order.indexOf(this.state.repeat) + 1) % 3];
    this.optimistic({ repeat: v });
    try { await api('/me/player/repeat', { method: 'PUT', query: { state: v } }); }
    catch (e) { toast(e.message, true); this.refreshState(); }
  },

  async transfer(deviceId) {
    this.unlock();
    try {
      await api('/me/player', { method: 'PUT', body: { device_ids: [deviceId], play: !!this.state?.playing } });
      this.activeDeviceId = deviceId;
      setTimeout(() => this.refreshState(), 800);
      return true;
    } catch (e) { toast(e.message, true); return false; }
  },

  optimistic(patch) {
    if (!this.state) return;
    this.setState({ ...this.state, ...patch });
  },
};

function deviceLabel() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return 'Android';
  if (/Windows/.test(ua)) return 'PC';
  if (/Mac/.test(ua)) return 'Mac';
  return 'Web';
}

// ======================================================================
// UI del player
// ======================================================================
const ui = {
  renderPlayer() {
    const s = player.state;
    const appEl = $('#app');
    appEl.classList.toggle('is-playing', !!s?.playing);
    $('#nowPlaying').classList.toggle('paused', !s?.playing);
    $('#nowPlaying').classList.toggle('is-playing', !!s?.playing);

    $('#pTitle').textContent = s?.name || 'Niente in riproduzione';
    $('#pArtist').textContent = s?.artists || 'Scegli una playlist';
    setImg($('#pCover'), s?.image);
    $('#npTitle').textContent = s?.name || '—';
    $('#npArtist').textContent = s?.artists || '—';
    setImg($('#npCover'), s?.imageLarge);
    $('#npBg').style.backgroundImage = s?.imageLarge ? `url("${s.imageLarge}")` : 'none';

    $$('[data-act="shuffle"]').forEach(b => b.classList.toggle('on', !!s?.shuffle));
    $$('[data-act="repeat"]').forEach(b => {
      b.classList.toggle('on', !!s?.repeat && s.repeat !== 'off');
      b.classList.toggle('rep-track', s?.repeat === 'track');
    });

    // evidenzia il brano corrente nelle liste
    $$('.row[data-uri]').forEach(r => {
      const on = r.dataset.uri === s?.uri;
      r.classList.toggle('playing', on);
      r.classList.toggle('paused', on && !s?.playing);
      const num = $('.num', r);
      if (num) num.innerHTML = on ? '<span class="eq"><i></i><i></i><i></i></span>' : esc(num.dataset.n || '');
    });

    this.renderDevicePill();
    this.renderProgress();
    mediaSession.update(s);
  },

  renderProgress() {
    const s = player.state;
    const pos = player.position();
    const dur = s?.duration || 0;
    const pct = dur ? Math.min(100, (pos / dur) * 100) : 0;
    if (!player.seeking) {
      [$('#pSeek'), $('#npSeek')].forEach(r => { r.value = Math.round(pct * 10); r.style.setProperty('--pct', pct + '%'); });
    }
    $('#pTime').textContent = $('#npTime').textContent = fmt(pos);
    $('#pDur').textContent = $('#npDur').textContent = fmt(dur);
    $('#player').style.setProperty('--mini-pct', pct + '%');
  },

  renderDevicePill() {
    const pill = $('#pDevice');
    if (!player.activeDeviceId) pill.textContent = player.sdkReady ? 'Pronto su questo dispositivo' : '';
    else pill.textContent = player.isLocal() ? 'Questo dispositivo' : '▸ ' + player.activeDeviceName;
    $('#npContext').textContent = player.activeDeviceId ? (player.isLocal() ? 'In riproduzione qui' : 'Su ' + player.activeDeviceName) : 'In riproduzione';
  },

  async openDevices() {
    const dlg = $('#devicesDialog');
    if (!dlg.open) dlg.showModal();
    const list = $('#devicesList');
    list.innerHTML = '<li class="skeleton" style="height:56px"></li>';
    try {
      const { devices = [] } = await api('/me/player/devices');
      // il player del browser potrebbe non essere ancora nella lista
      if (player.sdkReady && !devices.some(d => d.id === player.deviceId)) {
        devices.unshift({ id: player.deviceId, name: 'Questo dispositivo', type: 'Computer', is_active: player.isLocal() });
      }
      if (!devices.length) {
        list.innerHTML = `<li class="empty">Nessun dispositivo trovato.${player.sdkError ? '<br>' + esc(player.sdkError) : ''}<br>Apri l'app Spotify su telefono o PC e tocca «Aggiorna».</li>`;
        return;
      }
      list.innerHTML = devices.map(d => `
        <li><button type="button" data-device="${esc(d.id)}" class="${d.is_active ? 'active' : ''}">
          <svg viewBox="0 0 24 24">${d.type === 'Smartphone' ? '<rect x="7" y="3" width="10" height="18" rx="2"/><path d="M11 18h2"/>' : d.type === 'Speaker' ? '<rect x="6" y="3" width="12" height="18" rx="2"/><circle cx="12" cy="14" r="3"/>' : '<rect x="3" y="5" width="18" height="11" rx="2"/><path d="M8 20h8"/>'}</svg>
          <span><strong>${esc(d.id === player.deviceId ? 'Questo dispositivo (Onda)' : d.name)}</strong><small>${d.is_active ? 'In uso' : esc(d.type)}</small></span>
        </button></li>`).join('');
    } catch (e) {
      list.innerHTML = `<li class="empty">${esc(e.message)}</li>`;
    }
  },
};

function setImg(el, url) {
  if (url) { if (el.src !== url) el.src = url; el.style.visibility = 'visible'; }
  else { el.removeAttribute('src'); el.style.visibility = 'hidden'; }
}

// Controlli dalla schermata di blocco / cuffie
const mediaSession = {
  lastUri: null,
  init() {
    if (!('mediaSession' in navigator)) return;
    const ms = navigator.mediaSession;
    const h = (a, fn) => { try { ms.setActionHandler(a, fn); } catch {} };
    h('play', () => player.toggle());
    h('pause', () => player.toggle());
    h('nexttrack', () => player.next());
    h('previoustrack', () => player.prev());
    h('seekto', d => player.seek(d.seekTime * 1000));
  },
  update(s) {
    if (!('mediaSession' in navigator)) return;
    navigator.mediaSession.playbackState = s ? (s.playing ? 'playing' : 'paused') : 'none';
    if (!s?.uri || s.uri === this.lastUri) return;
    this.lastUri = s.uri;
    try {
      navigator.mediaSession.metadata = new MediaMetadata({
        title: s.name, artist: s.artists, album: s.album,
        artwork: s.imageLarge ? [{ src: s.imageLarge, sizes: '640x640', type: 'image/jpeg' }] : [],
      });
    } catch {}
  },
};

// ======================================================================
// Viste
// ======================================================================
const view = () => $('#view');
let renderToken = 0; // evita che risposte lente sovrascrivano una vista più recente

function tileHtml(e) {
  return `
    <div class="tile ${e.type === 'artist' ? 'round' : ''}" data-open="${esc(e.type)}/${esc(e.id)}" tabindex="0" role="link" aria-label="${esc(e.name)}">
      ${coverHtml(e.image, e.name)}
      <button class="tile-play" type="button" data-play-uri="${esc(e.uri)}" data-type="${esc(e.type)}" aria-label="Riproduci ${esc(e.name)}"><svg viewBox="0 0 24 24"><path d="M8 5l11 7-11 7z" class="fill"/></svg></button>
      <strong>${esc(e.name)}</strong>
      <span>${esc(e.sub || '')}</span>
    </div>`;
}

function entryFrom(obj) {
  if (!obj) return null;
  const type = obj.type;
  let sub = '';
  if (type === 'playlist') sub = 'Playlist · ' + (obj.owner?.display_name || '');
  else if (type === 'album') sub = (obj.album_type === 'single' ? 'Singolo' : 'Album') + ' · ' + artistsOf(obj);
  else if (type === 'artist') sub = 'Artista';
  else if (type === 'track') sub = 'Brano · ' + artistsOf(obj);
  return {
    type, id: obj.id, uri: obj.uri, name: obj.name || '',
    image: img(obj.images || obj.album?.images, 300), sub,
  };
}

function trackRowsHtml(tracks, { contextUri, showCover = true, fallbackImage = '' } = {}) {
  if (!tracks.length) return '<div class="empty">Nessun brano.</div>';
  return `<div class="row-list">${tracks.map((t, i) => {
    const cover = img(t.album?.images, 64) || fallbackImage;
    return `
    <div class="row" data-uri="${esc(t.uri)}" data-context="${esc(contextUri || '')}" data-index="${i}" tabindex="0" role="button" aria-label="Riproduci ${esc(t.name)}">
      <span class="num" data-n="${i + 1}">${i + 1}</span>
      ${showCover ? (cover ? `<img src="${esc(cover)}" alt="" loading="lazy" />` : '<div class="ph"></div>') : '<div class="ph"></div>'}
      <div class="txt"><strong>${esc(t.name)}</strong><span>${esc(artistsOf(t))}</span></div>
      <span class="dur">${fmt(t.duration_ms)}</span>
      <span></span>
    </div>`;
  }).join('')}</div>`;
}

function setActiveNav(name) {
  $$('[data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === name));
}

// ---------- Home ----------
async function renderHome() {
  setActiveNav('home');
  const tk = ++renderToken;
  const me = store.get('me');
  const saved = lib.saved();
  const recent = lib.recent();
  const history = lib.history().slice(0, 10);
  const hour = new Date().getHours();
  const hello = hour < 12 ? 'Buongiorno' : hour < 18 ? 'Buon pomeriggio' : 'Buonasera';

  view().innerHTML = `
    <div class="hero">
      <h1>${hello}${me?.display_name ? ', ' + esc(me.display_name.split(' ')[0]) : ''}</h1>
      <p>Incolla il link di una playlist, un album o un brano di Spotify e ascoltalo qui.</p>
      <form id="heroLink" autocomplete="off">
        <label for="heroInput" class="sr-only">Link Spotify</label>
        <input id="heroInput" type="text" inputmode="url" placeholder="https://open.spotify.com/playlist/…" />
        <button class="btn primary" type="submit">Apri</button>
      </form>
    </div>

    <section class="section">
      <div class="section-head"><h2>Salvati</h2></div>
      ${saved.length ? `<div class="grid">${saved.map(tileHtml).join('')}</div>` : '<div class="empty">Apri una playlist e tocca «Salva» per trovarla qui, anche offline.</div>'}
    </section>

    ${recent.length ? `<section class="section">
      <div class="section-head"><h2>Ascoltati di recente</h2><button type="button" data-clear="recent">Cancella</button></div>
      <div class="grid">${recent.slice(0, 12).map(tileHtml).join('')}</div>
    </section>` : ''}

    <section class="section">
      <div class="section-head"><h2>Le tue playlist</h2><a href="#/library">Tutte</a></div>
      <div id="homePlaylists" class="grid">${'<div class="skeleton" style="aspect-ratio:.8"></div>'.repeat(4)}</div>
    </section>

    ${history.length ? `<section class="section">
      <div class="section-head"><h2>Cronologia brani</h2><button type="button" data-clear="history">Cancella</button></div>
      <div class="row-list">${history.map((t, i) => `
        <div class="row" data-uri="${esc(t.uri)}" data-single="1" tabindex="0" role="button">
          <span class="num" data-n="${i + 1}">${i + 1}</span>
          ${t.image ? `<img src="${esc(t.image)}" alt="" loading="lazy" />` : '<div class="ph"></div>'}
          <div class="txt"><strong>${esc(t.name)}</strong><span>${esc(t.artists)}</span></div>
          <span class="dur">${new Date(t.at).toLocaleDateString('it-IT', { day: '2-digit', month: 'short' })}</span><span></span>
        </div>`).join('')}</div>
    </section>` : ''}
  `;

  try {
    const playlists = await getMyPlaylists();
    if (tk !== renderToken) return;
    $('#homePlaylists').innerHTML = playlists.length
      ? playlists.slice(0, 8).map(p => tileHtml(entryFrom(p))).join('')
      : '<div class="empty">Non hai ancora playlist.</div>';
  } catch (e) {
    if (tk !== renderToken) return;
    $('#homePlaylists').innerHTML = `<div class="empty">${esc(e.message)}</div>`;
  }
}

async function getMyPlaylists(force = false) {
  const cached = !force && lib.cache.get('myPlaylists', 10 * 60 * 1000);
  if (cached) return cached;
  const { items } = await apiAll('/me/playlists', {}, 300);
  // salviamo solo i campi utili per non riempire il localStorage
  const slim = items.filter(Boolean).map(p => ({
    type: 'playlist', id: p.id, uri: p.uri, name: p.name,
    images: (p.images || []).slice(0, 3), owner: { display_name: p.owner?.display_name },
    total: p.items?.total ?? p.tracks?.total ?? null,
  }));
  lib.cache.set('myPlaylists', slim);
  return slim;
}

// ---------- Libreria ----------
async function renderLibrary() {
  setActiveNav('library');
  const tk = ++renderToken;
  view().innerHTML = `
    <h1 class="view-title">Libreria</h1>
    <div class="grid" id="libGrid">
      <div class="tile" data-open="liked/me" tabindex="0" role="link">
        <div class="cover cover-fallback"><svg viewBox="0 0 24 24" style="width:42px;height:42px"><path class="fill" d="M12 20s-7-4.4-7-10a4 4 0 017-2.6A4 4 0 0119 10c0 5.6-7 10-7 10z"/></svg></div>
        <strong>Brani che ti piacciono</strong><span>Playlist</span>
      </div>
      ${'<div class="skeleton" style="aspect-ratio:.8"></div>'.repeat(5)}
    </div>
    <p style="margin-top:20px"><button class="btn ghost small" id="reloadLib" type="button">Aggiorna playlist</button></p>`;
  const load = async force => {
    try {
      const list = await getMyPlaylists(force);
      if (tk !== renderToken) return;
      const liked = $('#libGrid .tile').outerHTML;
      $('#libGrid').innerHTML = liked + list.map(p => tileHtml(entryFrom(p))).join('');
    } catch (e) { toast(e.message, true); }
  };
  $('#reloadLib').onclick = () => load(true);
  load(false);
}

// ---------- Cerca ----------
let searchType = 'track';
async function renderSearch(q = '') {
  setActiveNav('search');
  ++renderToken;
  view().innerHTML = `
    <h1 class="view-title">Cerca</h1>
    <form id="searchForm" class="field-row" style="margin-bottom:14px" autocomplete="off">
      <label for="searchInput" class="sr-only">Cerca</label>
      <input id="searchInput" type="text" placeholder="Brani, artisti, album, playlist" value="${esc(q)}" />
      <button class="btn primary" type="submit">Cerca</button>
    </form>
    <div class="chips">
      ${[['track', 'Brani'], ['playlist', 'Playlist'], ['album', 'Album'], ['artist', 'Artisti']].map(([t, l]) => `<button type="button" class="chip ${t === searchType ? 'active' : ''}" data-stype="${t}">${l}</button>`).join('')}
    </div>
    <div id="searchResults">${q ? '' : '<div class="empty">Scrivi qualcosa per iniziare.</div>'}</div>
    <p id="searchMore" hidden style="margin-top:16px"><button class="btn ghost small" type="button">Altri risultati</button></p>`;
  const input = $('#searchInput');
  if (!q) input.focus();
  $('#searchForm').onsubmit = e => { e.preventDefault(); location.hash = '#/search/' + encodeURIComponent(input.value.trim()); };
  $$('[data-stype]').forEach(c => c.onclick = () => { searchType = c.dataset.stype; renderSearch(input.value.trim()); });
  if (q) doSearch(q, 0);
}

async function doSearch(q, offset) {
  const tk = renderToken;
  const box = $('#searchResults');
  if (!offset) box.innerHTML = '<div class="skeleton" style="height:200px"></div>';
  try {
    // dal 2026 il limite massimo per pagina della ricerca è 10
    const res = await api('/search', { query: { q, type: searchType, limit: 10, offset } });
    if (tk !== renderToken) return;
    const page = res[searchType + 's'];
    const items = (page?.items || []).filter(Boolean);
    let html;
    if (searchType === 'track') html = trackRowsHtml(items).replace('class="row-list"', 'class="row-list" data-tracks-single="1"');
    else html = `<div class="grid">${items.map(x => tileHtml(entryFrom(x))).join('')}</div>`;
    if (!items.length && !offset) html = '<div class="empty">Nessun risultato.</div>';
    if (offset) box.insertAdjacentHTML('beforeend', html); else box.innerHTML = html;
    if (searchType === 'track') $$('#searchResults .row').forEach(r => { r.dataset.single = '1'; });
    const more = $('#searchMore');
    more.hidden = !page?.next || offset >= 40;
    more.querySelector('button').onclick = () => doSearch(q, offset + 10);
    ui.renderPlayer();
  } catch (e) {
    if (tk === renderToken) box.innerHTML = `<div class="empty">${esc(e.message)}</div>`;
  }
}

// ---------- Dettaglio: playlist / album / artista / brano / preferiti ----------
async function renderDetail(type, id) {
  setActiveNav('');
  const tk = ++renderToken;
  view().innerHTML = `
    <div class="detail-head"><div class="cover skeleton"></div><div style="flex:1"><div class="skeleton" style="height:16px;width:80px"></div><div class="skeleton" style="height:42px;width:70%;margin:10px 0"></div><div class="skeleton" style="height:14px;width:40%"></div></div></div>
    <div class="skeleton" style="height:300px"></div>`;
  try {
    let head, tracks = [], notice = '', contextUri, entry, fallbackImage = '';
    if (type === 'playlist') {
      const p = await api(`/playlists/${id}`);
      contextUri = p.uri;
      entry = entryFrom(p);
      head = { kind: 'Playlist', name: p.name, image: img(p.images, 640), sub: [p.owner?.display_name, stripHtml(p.description)].filter(Boolean).join(' · ') };
      const embedded = p.items?.items || p.tracks?.items;
      try {
        let list = embedded;
        if (!list || (p.items?.next || p.tracks?.next)) list = (await apiAll(`/playlists/${id}/items`, {}, 1000)).items;
        tracks = list.map(x => x.item || x.track).filter(t => t && t.uri && !t.is_local);
      } catch (e) {
        if (e.status === 403 || e.status === 404) {
          notice = 'Spotify mostra l\'elenco dei brani solo per le playlist create da te o di cui sei collaboratore. Puoi comunque riprodurla per intero con il tasto ▶.';
        } else throw e;
      }
    } else if (type === 'album') {
      const a = await api(`/albums/${id}`);
      contextUri = a.uri;
      entry = entryFrom(a);
      fallbackImage = img(a.images, 64);
      head = { kind: a.album_type === 'single' ? 'Singolo' : 'Album', name: a.name, image: img(a.images, 640), sub: `${artistsOf(a)} · ${(a.release_date || '').slice(0, 4)} · ${a.total_tracks} brani` };
      tracks = a.tracks?.items || [];
      if (a.tracks?.next) tracks = tracks.concat((await apiAll(a.tracks.next)).items);
    } else if (type === 'artist') {
      const ar = await api(`/artists/${id}`);
      contextUri = ar.uri;
      entry = entryFrom(ar);
      head = { kind: 'Artista', name: ar.name, image: img(ar.images, 640), sub: (ar.genres || []).slice(0, 3).join(', ') };
      try {
        const albums = await api(`/artists/${id}/albums`, { query: { include_groups: 'album,single', limit: 10 } });
        head.albums = (albums.items || []).filter(Boolean);
      } catch { head.albums = []; }
    } else if (type === 'track') {
      const t = await api(`/tracks/${id}`);
      entry = entryFrom(t);
      head = { kind: 'Brano', name: t.name, image: img(t.album?.images, 640), sub: `${artistsOf(t)} · ${t.album?.name || ''}` };
      tracks = [t];
    } else if (type === 'liked') {
      const me = store.get('me');
      contextUri = me?.id ? `spotify:user:${me.id}:collection` : null;
      head = { kind: 'Playlist', name: 'Brani che ti piacciono', image: '', sub: 'La tua raccolta' };
      tracks = (await apiAll('/me/tracks', {}, 500)).items.map(x => x.track).filter(Boolean);
    } else {
      throw new Error('Link non supportato.');
    }
    if (tk !== renderToken) return;

    const canSave = entry && type !== 'liked';
    const saved = canSave && lib.isSaved(entry.uri);
    view().innerHTML = `
      <div class="detail-head">
        ${coverHtml(head.image, head.name)}
        <div><span class="kind">${esc(head.kind)}</span><h1>${esc(head.name)}</h1><p>${esc(head.sub || '')}${tracks.length > 1 ? ' · ' + tracks.length + ' brani' : ''}</p></div>
      </div>
      <div class="detail-actions">
        <button class="play-btn xl" type="button" id="detailPlay" aria-label="Riproduci"><svg viewBox="0 0 24 24"><path d="M8 5l11 7-11 7z" class="fill"/></svg></button>
        ${contextUri && tracks.length > 1 ? '<button class="btn ghost small" type="button" id="detailShuffle">Casuale</button>' : ''}
        ${canSave ? `<button class="btn ghost small" type="button" id="detailSave">${saved ? '✓ Salvato' : '+ Salva'}</button>` : ''}
        ${entry ? `<button class="btn ghost small" type="button" id="detailShare">Copia link</button>` : ''}
      </div>
      ${notice ? `<div class="notice">${esc(notice)}</div>` : ''}
      ${type === 'artist'
        ? `<section class="section"><div class="section-head"><h2>Album e singoli</h2></div><div class="grid">${head.albums.map(a => tileHtml(entryFrom(a))).join('') || '<div class="empty">Nessun album.</div>'}</div></section>`
        : tracks.length ? trackRowsHtml(tracks, { contextUri, fallbackImage }) : ''}
    `;

    const meta = entry ? { ...entry, image: entry.image || head.image } : (type === 'liked' ? { type: 'liked', id: 'me', uri: contextUri, name: head.name, sub: 'Playlist', image: '' } : null);
    // le righe dei preferiti senza contesto valido suonano come lista di brani
    if (type === 'liked' && !contextUri) $$('#view .row').forEach(r => { r.dataset.context = ''; r.dataset.list = '1'; });
    view()._tracks = tracks;
    view()._meta = meta;

    $('#detailPlay').onclick = () => {
      if (type === 'track') return player.play({ uris: [entry.uri], meta });
      if (contextUri) return player.play({ contextUri, meta });
      player.play({ uris: tracks.slice(0, 100).map(t => t.uri), meta });
    };
    const sh = $('#detailShuffle');
    if (sh) sh.onclick = async () => {
      const idx = Math.floor(Math.random() * tracks.length);
      await player.play({ contextUri, offsetIndex: idx, meta });
      try { await api('/me/player/shuffle', { method: 'PUT', query: { state: true } }); player.optimistic({ shuffle: true }); } catch {}
    };
    const sv = $('#detailSave');
    if (sv) sv.onclick = () => {
      const now = lib.toggleSaved({ ...entry, image: entry.image || head.image });
      sv.textContent = now ? '✓ Salvato' : '+ Salva';
      toast(now ? 'Salvato su questo dispositivo' : 'Rimosso dai salvati');
    };
    const shr = $('#detailShare');
    if (shr) shr.onclick = async () => {
      const link = `https://open.spotify.com/${entry.type}/${entry.id}`;
      try { await navigator.clipboard.writeText(link); toast('Link copiato'); } catch { prompt('Copia il link', link); }
    };
    ui.renderPlayer();
  } catch (e) {
    if (tk !== renderToken) return;
    view().innerHTML = `<div class="empty">${e.status === 404 ? 'Contenuto non trovato o non disponibile in Italia.' : esc(e.message)}</div>`;
  }
}

function stripHtml(s = '') {
  const d = document.createElement('div');
  d.innerHTML = s;
  return (d.textContent || '').trim();
}

// ---------- Impostazioni ----------
function renderSettings() {
  setActiveNav('settings');
  ++renderToken;
  const me = store.get('me');
  view().innerHTML = `
    <h1 class="view-title">Impostazioni</h1>
    <div class="settings-list">
      <div class="setting">
        <h3>Account</h3>
        <div class="user-chip">${me?.images?.[0]?.url ? `<img src="${esc(me.images[0].url)}" alt="" />` : '<div class="cover-fallback" style="width:44px;height:44px;border-radius:50%">' + esc((me?.display_name || '?')[0]) + '</div>'}
          <div><strong>${esc(me?.display_name || 'Utente Spotify')}</strong><p>${esc(me?.id || '')}</p></div></div>
        <div class="actions"><button class="btn ghost small" type="button" id="logoutBtn">Esci</button></div>
      </div>
      <div class="setting">
        <h3>Player</h3>
        <p>${player.sdkReady ? 'Il browser è pronto per riprodurre musica.' : esc(player.sdkError || 'Il player del browser si sta avviando…')}</p>
        <div class="actions"><button class="btn ghost small" type="button" data-open-devices>Scegli dispositivo</button></div>
      </div>
      <div class="setting">
        <h3>Dati salvati sul dispositivo</h3>
        <p>${lib.saved().length} salvati · ${lib.recent().length} recenti · ${lib.history().length} brani in cronologia. Il login resta su questo dispositivo e non viene esportato.</p>
        <div class="actions">
          <button class="btn ghost small" type="button" id="exportBtn">Esporta backup</button>
          <label class="btn ghost small" for="importFile" style="cursor:pointer">Importa backup</label>
          <input id="importFile" type="file" accept="application/json" hidden />
          <button class="btn danger small" type="button" id="wipeBtn">Cancella tutto</button>
        </div>
      </div>
      <div class="setting">
        <h3>App Spotify collegata</h3>
        <p>Client ID: <code>${esc(auth.clientId)}</code><br>Redirect URI: <code>${esc(REDIRECT_URI)}</code></p>
        <div class="actions"><button class="btn ghost small" type="button" id="changeClient">Cambia Client ID</button></div>
      </div>
      <div class="setting">
        <h3>Installa sul telefono</h3>
        <p>iPhone: Safari → Condividi → «Aggiungi alla schermata Home». Android: Chrome → menu ⋮ → «Installa app».</p>
      </div>
    </div>`;

  $('#logoutBtn').onclick = () => { player.sdk?.disconnect(); auth.logout(); location.hash = ''; boot(); };
  $('#exportBtn').onclick = () => {
    const blob = new Blob([JSON.stringify({ app: 'onda', version: 1, data: store.exportAll() }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `onda-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  $('#importFile').onchange = async e => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const json = JSON.parse(await file.text());
      if (json.app !== 'onda' || typeof json.data !== 'object') throw new Error();
      ['saved', 'recent', 'history', 'volume'].forEach(k => { if (k in json.data) store.set(k, json.data[k]); });
      toast('Backup importato');
      renderSettings();
    } catch { toast('File di backup non valido', true); }
  };
  $('#wipeBtn').onclick = () => {
    if (!confirm('Cancellare salvati, cronologia e login da questo dispositivo?')) return;
    player.sdk?.disconnect();
    store.clearAll();
    location.hash = '';
    location.reload();
  };
  $('#changeClient').onclick = () => { auth.logout(); store.remove('clientId'); boot(); };
}

// ======================================================================
// Router
// ======================================================================
function route() {
  const parts = location.hash.replace(/^#\/?/, '').split('/');
  const [name, a, b] = parts;
  $('#view').scrollTop = 0;
  if (name === 'search') return renderSearch(a ? decodeURIComponent(a) : '');
  if (name === 'library') return renderLibrary();
  if (name === 'settings') return renderSettings();
  if (['playlist', 'album', 'artist', 'track', 'liked'].includes(name) && a) return renderDetail(name, a);
  if (name === 'open' && a) { const l = parseSpotifyLink(decodeURIComponent(a + (b ? '/' + b : ''))); if (l?.id) { location.replace(`#/${l.type}/${l.id}`); return; } }
  return renderHome();
}

function openLink(value) {
  const l = parseSpotifyLink(value);
  if (!l) return toast('Link non riconosciuto. Usa un link open.spotify.com di playlist, album, brano o artista.', true);
  if (l.short) return toast('I link brevi spotify.link non si possono leggere: aprilo nel browser e copia l\'indirizzo completo open.spotify.com.', true);
  if (l.type === 'show' || l.type === 'episode') return toast('Podcast non ancora supportati.', true);
  location.hash = `#/${l.type}/${l.id}`;
}

// ======================================================================
// Eventi globali
// ======================================================================
function bindGlobal() {
  window.addEventListener('hashchange', route);

  $('#linkForm').addEventListener('submit', e => { e.preventDefault(); openLink($('#linkInput').value); $('#linkInput').value = ''; $('#linkInput').blur(); });
  // incollare un link lo apre subito
  $('#linkInput').addEventListener('paste', () => setTimeout(() => { const v = $('#linkInput').value; if (parseSpotifyLink(v)?.id) { openLink(v); $('#linkInput').value = ''; } }, 0));

  document.addEventListener('submit', e => {
    if (e.target.id === 'heroLink') { e.preventDefault(); openLink($('#heroInput').value); }
  });

  document.addEventListener('click', e => {
    const t = e.target;

    const act = t.closest('[data-act]');
    if (act) {
      const a = act.dataset.act;
      if (a === 'toggle') player.toggle();
      if (a === 'next') player.next();
      if (a === 'prev') player.prev();
      if (a === 'shuffle') player.toggleShuffle();
      if (a === 'repeat') player.cycleRepeat();
      return;
    }

    const playBtn = t.closest('[data-play-uri]');
    if (playBtn) {
      e.stopPropagation();
      const tile = playBtn.closest('[data-open]');
      const [type, id] = tile.dataset.open.split('/');
      const entry = lib.saved().concat(lib.recent()).find(x => x.uri === playBtn.dataset.playUri) || { type, id, uri: playBtn.dataset.playUri, name: tile.querySelector('strong')?.textContent || '', sub: tile.querySelector('span')?.textContent || '', image: tile.querySelector('img')?.src || '' };
      if (type === 'liked') { location.hash = '#/liked/me'; return; }
      if (type === 'track') player.play({ uris: [entry.uri], meta: entry });
      else player.play({ contextUri: entry.uri, meta: entry });
      return;
    }

    const open = t.closest('[data-open]');
    if (open) { location.hash = '#/' + open.dataset.open; return; }

    const row = t.closest('.row[data-uri]');
    if (row) { playRow(row); return; }

    const clr = t.closest('[data-clear]');
    if (clr) { store.set(clr.dataset.clear, []); renderHome(); return; }

    const dev = t.closest('[data-device]');
    if (dev) { player.transfer(dev.dataset.device).then(ok => ok && $('#devicesDialog').close()); return; }

    if (t.closest('[data-open-devices]') || t.closest('#devicesBtn')) { ui.openDevices(); return; }
    if (t.closest('#refreshDevices')) { ui.openDevices(); return; }
    if (t.closest('[data-close]')) { t.closest('dialog').close(); return; }
    if (t.closest('#npOpen')) { $('#nowPlaying').hidden = false; return; }
    if (t.closest('#npClose')) { $('#nowPlaying').hidden = true; return; }
  });

  document.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('.row[data-uri], [data-open]')) {
      e.preventDefault();
      e.target.click();
    }
    if (e.key === 'Escape' && !$('#nowPlaying').hidden) $('#nowPlaying').hidden = true;
    if (e.code === 'Space' && !e.target.matches('input, textarea, button, [role="button"], [role="link"]')) { e.preventDefault(); player.toggle(); }
  });

  // chiudi il dialog toccando lo sfondo
  $('#devicesDialog').addEventListener('click', e => { if (e.target === e.currentTarget) e.currentTarget.close(); });

  // slider posizione
  [$('#pSeek'), $('#npSeek')].forEach(r => {
    r.addEventListener('input', () => {
      player.seeking = true;
      r.style.setProperty('--pct', r.value / 10 + '%');
      const ms = (r.value / 1000) * (player.state?.duration || 0);
      $('#pTime').textContent = $('#npTime').textContent = fmt(ms);
    });
    r.addEventListener('change', () => {
      player.seeking = false;
      if (player.state) player.seek((r.value / 1000) * player.state.duration);
    });
  });

  // slider volume
  const vol = store.get('volume', 70);
  [$('#pVol'), $('#npVol')].forEach(r => {
    r.value = vol; r.style.setProperty('--pct', vol + '%');
    r.addEventListener('input', () => {
      const v = Number(r.value);
      [$('#pVol'), $('#npVol')].forEach(x => { x.value = v; x.style.setProperty('--pct', v + '%'); });
      player.setVolume(v);
    });
  });

  // swipe giù per chiudere la schermata "in riproduzione"
  let startY = null;
  $('#nowPlaying').addEventListener('touchstart', e => { if (!e.target.matches('input')) startY = e.touches[0].clientY; }, { passive: true });
  $('#nowPlaying').addEventListener('touchend', e => {
    if (startY !== null && e.changedTouches[0].clientY - startY > 110) $('#nowPlaying').hidden = true;
    startY = null;
  });

  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') player.refreshState(); });

  // aggiornamento fluido della barra di avanzamento
  setInterval(() => { if (player.state?.playing) ui.renderProgress(); }, 500);
}

function playRow(row) {
  const uri = row.dataset.uri;
  const v = view();
  if (row.dataset.single) return player.play({ uris: [uri], meta: { type: 'track', id: uri.split(':')[2], uri, name: $('strong', row)?.textContent || '', sub: 'Brano · ' + ($('.txt span', row)?.textContent || ''), image: $('img', row)?.src || '' } });
  const ctx = row.dataset.context;
  if (ctx) return player.play({ contextUri: ctx, offsetUri: uri, meta: v._meta });
  // nessun contesto (es. preferiti senza id utente): suona la lista a partire dal brano
  const list = (v._tracks || []).map(t => t.uri);
  const i = Math.max(0, list.indexOf(uri));
  player.play({ uris: list.slice(i, i + 100), meta: v._meta });
}

// ======================================================================
// Avvio
// ======================================================================
function show(id) {
  ['setup', 'login', 'app'].forEach(s => { $('#' + s).hidden = s !== id; });
}

let globalBound = false;

async function boot() {
  // 1) Client ID mancante → configurazione
  if (!auth.clientId) {
    show('setup');
    $('#redirectUri').textContent = REDIRECT_URI;
    $('#copyRedirect').onclick = async () => {
      try { await navigator.clipboard.writeText(REDIRECT_URI); toast('Copiato'); } catch { prompt('Copia questo indirizzo', REDIRECT_URI); }
    };
    $('#setupForm').onsubmit = e => {
      e.preventDefault();
      const v = $('#clientIdInput').value.trim();
      if (!/^[a-f0-9]{32}$/i.test(v)) return toast('Il Client ID deve essere di 32 caratteri (lettere a-f e numeri).', true);
      store.set('clientId', v);
      boot();
    };
    return;
  }

  // 2) Ritorno dal login Spotify
  try {
    await auth.handleCallback();
  } catch (e) {
    show('login');
    $('#loginError').hidden = false;
    $('#loginError').textContent = e.message;
  }

  // 3) Non loggato → schermata di accesso
  if (!auth.isLoggedIn()) {
    show('login');
    $('#loginBtn').onclick = () => auth.login();
    $('#editClientId').onclick = () => { store.remove('clientId'); boot(); };
    return;
  }

  // 4) App
  show('app');
  if (!globalBound) { bindGlobal(); mediaSession.init(); globalBound = true; }
  try {
    const me = await api('/me');
    store.set('me', { id: me.id, display_name: me.display_name, images: me.images });
  } catch (e) {
    if (!auth.isLoggedIn()) return boot();
    toast(e.message, true);
  }
  player.init();
  route();
}

if ('serviceWorker' in navigator && location.protocol === 'https:') {
  window.addEventListener('load', () => navigator.serviceWorker.register('sw.js').catch(() => {}));
}

// esposto solo per i test automatici
window.__onda = { parseSpotifyLink };

boot();
