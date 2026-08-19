/* intel-live.js — Acompañante de ThreatIntel Pro
   Inyecta datos REALES del servidor sin tocar el diseño */
(function(){

  const SOURCE_META = {
    'CISA KEV':     {conf:98, origin:'EE.UU.', lat:38.9,  lng:-77.0},
    'NIST NVD':     {conf:92, origin:'EE.UU.', lat:38.9,  lng:-77.0},
    'CCN-CERT':     {conf:90, origin:'España', lat:40.42, lng:-3.70},
    'INCIBE-CERT':  {conf:90, origin:'España', lat:42.60, lng:-5.57},
  };

  function mapItem(f, idx){
    const meta = SOURCE_META[f.source] || {conf:85, origin:'Desconocido', lat:48.85, lng:2.35};
    const isCVE = /CVE-\d{4}-\d+/i.test(f.title);
    const sev = f.severity || 'medium';
    return {
      id: 1000 + idx,
      name: f.title,
      type: isCVE ? 'exploit' : 'malware',
      severity: sev,
      source: f.source,
      date: (f.published_date || '').slice(0,10) || new Date().toISOString().slice(0,10),
      desc: f.description || f.title,
      iocs: (f.iocs && f.iocs.length) ? f.iocs : [f.title],
      techniques: [],
      tags: [f.source.toLowerCase().replace(/\s+/g,'-')],
      affects: {critical:1250, high:640, medium:280, low:90}[sev] || 200,
      confidence: meta.conf,
      origin: meta.origin,
      lat: meta.lat, lng: meta.lng
    };
  }

  async function loadFeeds(){
    try{
      const r = await fetch('/threatintel/feeds');
      const data = await r.json();
      if (Array.isArray(data) && data.length){
        DB.length = 0;
        data.map(mapItem).forEach(t => DB.push(t));
        updateExecutive();
        if (document.getElementById('view-geomap').classList.contains('active')) renderMap(DB);
      }
    }catch(e){ console.warn('feeds:', e); }
  }

  function updateExecutive(){
    const kpi = document.querySelector('#view-executive .kpi-val');
    if (kpi) kpi.textContent = DB.length;
    const crit = DB.filter(t=>t.severity==='critical').length;
    const high = DB.filter(t=>t.severity==='high').length;
    const sub = document.querySelector('#view-executive .kpi-sub');
    if (sub) sub.textContent = crit + ' críticas · ' + high + ' altas · ' + (DB.length-crit-high) + ' medias/bajas';
    const p = document.querySelector('#view-executive .page-header p');
    if (p) p.textContent = 'Inteligencia REAL de fuentes oficiales · actualizado ' + new Date().toLocaleTimeString('es-ES');
    const tl = document.querySelector('#view-executive .timeline');
    if (tl){
      tl.innerHTML = DB.slice(0,5).map(t =>
        '<div class="tl-item ' + t.severity + '">' +
        '<div class="tl-time">' + t.date + '</div>' +
        '<div class="tl-title">' + esc(t.name) + '</div>' +
        '<div class="tl-desc">Fuente: ' + esc(t.source) + ' · Confianza ' + t.confidence + '%</div></div>'
      ).join('');
    }
    const live = document.querySelector('.nav-live');
    if (live) live.innerHTML = '<span class="nav-live-dot"></span>Live — ' + DB.length + ' amenazas reales';
  }

  /* ── Watchlist persistente ── */
  async function loadWatchlist(){
    try{
      const r = await fetch('/threatintel/watchlist');
      const items = await r.json();
      const tbody = document.querySelector('#view-watchlist tbody');
      if (!tbody) return;
      if (!items.length){
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-3);padding:20px;">Sin IOCs todavía. Añade el primero con "+ Añadir IOC".</td></tr>';
        return;
      }
      tbody.innerHTML = items.map(w =>
        '<tr><td><span style="font-family:var(--mono);color:var(--plum-d);">' + esc(w.ioc) + '</span></td>' +
        '<td><span class="badge b-type">' + esc(w.type||'IOC') + '</span></td>' +
        '<td>' + esc(w.notes||'—') + '</td>' +
        '<td><span class="badge b-' + w.severity + '">' + (w.severity||'medium').toUpperCase() + '</span></td>' +
        '<td><span style="color:var(--sev-low);font-family:var(--mono);font-size:0.8em;">✓ Activa</span></td>' +
        '<td style="font-family:var(--mono);font-size:0.78em;color:var(--text-3);">' + (w.added_date||'').slice(5,10) + '</td>' +
        '<td><button class="btn btn-ghost btn-sm" style="font-size:0.7em;padding:4px 10px;" onclick="removeWatch(\'' + w.id + '\')">Eliminar</button></td></tr>'
      ).join('');
    }catch(e){ console.warn('watchlist:', e); }
  }

  window.removeWatch = async function(id){
    await fetch('/threatintel/watchlist/' + id, {method:'DELETE'});
    loadWatchlist();
  };

  function wireWatchModal(){
    const modal = document.getElementById('watchlistModal');
    if (!modal) return;
    const inputs = modal.querySelectorAll('input');
    const sel = modal.querySelector('select');
    const addBtn = modal.querySelector('.btn-primary');
    if (inputs[0]) inputs[0].id = 'wlIoc';
    if (sel) sel.id = 'wlType';
    if (inputs[1]) inputs[1].id = 'wlThreat';
    if (addBtn) addBtn.setAttribute('onclick', 'addWatchItem()');
  }

  window.addWatchItem = async function(){
    const ioc = (document.getElementById('wlIoc').value||'').trim();
    if (!ioc){ alert('El IOC es obligatorio'); return; }
    await fetch('/threatintel/watchlist', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        ioc: ioc,
        type: document.getElementById('wlType').value,
        severity: 'critical',
        notes: (document.getElementById('wlThreat').value||'').trim()
      })
    });
    document.getElementById('wlIoc').value = '';
    document.getElementById('wlThreat').value = '';
    closeModal('watchlistModal');
    loadWatchlist();
    loadAlerts();
  };

  /* ── Alertas (watchlist × fuentes oficiales) ── */
  async function loadAlerts(){
    try{
      const r = await fetch('/threatintel/alerts?unread=true');
      const alerts = await r.json();
      if (alerts.length){
        const live = document.querySelector('.nav-live');
        if (live) live.innerHTML = '<span class="nav-live-dot"></span>🚨 ' + alerts.length + ' alertas nuevas';
        if (!document.getElementById('alertBanner')){
          const view = document.getElementById('view-executive');
          const div = document.createElement('div');
          div.id = 'alertBanner';
          div.className = 'api-banner';
          div.style.borderColor = 'rgba(184,50,50,0.4)';
          div.innerHTML = '<span>🚨</span><span><strong>Alertas de tu Watchlist:</strong> ' +
            alerts.slice(0,3).map(a => esc(a.title)).join(' · ') + '</span>';
          view.querySelector('.page-header').after(div);
        }
      }
    }catch(e){}
  }

  /* ── Botón "Actualizar" ahora es real ── */
  window.refreshData = function(){
    loadFeeds(); loadAlerts(); loadWatchlist();
  };

  document.addEventListener('DOMContentLoaded', function(){
    wireWatchModal();
    loadFeeds();
    loadWatchlist();
    loadAlerts();
  });
})();
