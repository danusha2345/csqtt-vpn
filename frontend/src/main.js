import './style.css';

const $ = (id) => document.getElementById(id);
const App = () => window.go.main.App;
const rt = () => window.runtime;

let connected = false;
let stateName = 'off'; // off | connecting | connected
let logLines = []; // [{line, cls, count}]

function fmtBytes(n) {
    const f = Number(n) || 0;
    if (f >= 1 << 30) return (f / (1 << 30)).toFixed(2) + ' ГБ';
    if (f >= 1 << 20) return (f / (1 << 20)).toFixed(2) + ' МБ';
    if (f >= 1 << 10) return (f / (1 << 10)).toFixed(1) + ' КБ';
    return f + ' Б';
}

function collect() {
    return {
        server: $('server').value.trim(),
        password: $('password').value.trim(),
        vkLinks: $('vk').value,
        workers: parseInt($('workers').value, 10) || 12,
        systemVPN: $('systemVPN').checked,
        excludes: $('excludes').value,
    };
}

function setFields(s) {
    $('server').value = s.server || '';
    $('password').value = s.password || '';
    $('vk').value = s.vkLinks || '';
    $('workers').value = s.workers || 12;
    $('systemVPN').checked = !!s.systemVPN;
    $('excludes').value = s.excludes || '';
}

function save() { App().SaveSettings(collect()); }

async function loadSettings() {
    try { setFields(await App().LoadSettings()); } catch (e) { /* до инжекта bindings */ }
}

// ─── профили ───
async function refreshProfiles(selected) {
    try {
        const names = (await App().ListProfiles()) || [];
        const sel = $('profileSel');
        sel.innerHTML = '<option value="">— текущий —</option>';
        for (const n of names) {
            const o = document.createElement('option');
            o.value = n; o.textContent = n;
            if (n === selected) o.selected = true;
            sel.appendChild(o);
        }
    } catch (e) { /* ignore */ }
}

function setState(state) {
    const power = $('power'), dot = $('connDot');
    const status = $('status'), sub = $('statusSub');
    let p = 'off', d = 'off', title = 'Отключено', subtitle = 'нажми, чтобы подключиться';
    switch (state) {
        case 'connecting':
            p = d = 'connecting'; title = 'Подключение…'; subtitle = 'устанавливаю туннель · клик — отмена';
            connected = false; break;
        case 'connected-vpn':
            p = d = 'connected'; title = 'Защищено'; subtitle = 'системный VPN · весь трафик';
            connected = true; break;
        case 'connected-socks':
            p = d = 'connected'; title = 'Подключено'; subtitle = 'SOCKS5 · 127.0.0.1:1080';
            connected = true; break;
        default:
            connected = false;
            $('downRate').textContent = '—'; $('upRate').textContent = '—';
            $('totals').textContent = '↓ 0 Б · ↑ 0 Б';
    }
    stateName = (state === 'connecting') ? 'connecting' : (connected ? 'connected' : 'off');
    power.dataset.state = p;
    dot.dataset.state = d;
    status.textContent = title;
    sub.textContent = subtitle;
    document.body.dataset.state = (p === 'connected') ? 'connected' : (p === 'connecting' ? 'connecting' : 'off');
    power.setAttribute('aria-label', connected ? 'Отключить' : 'Подключить');
}

function classOf(line) {
    if (/ошибк|error|fatal|fail|unreachable/i.test(line)) return 'err';
    if (/warn|не удалось|повтор|retry|⚠/i.test(line)) return 'warn';
    if (/✅|подключено|защищено|активен|handshake получен|→ OK\b/i.test(line)) return 'ok';
    return '';
}

function renderLog() {
    const log = $('log');
    log.innerHTML = logLines.map((l) => {
        const text = escapeHtml(l.line) + (l.count > 1 ? `  <em>×${l.count}</em>` : '');
        return l.cls ? `<span class="${l.cls}">${text}</span>` : text;
    }).join('\n');
    log.scrollTop = log.scrollHeight; // автоскролл
}

// Батчинг рендера: при потоке логов (проблемы с подключением) перерисовка
// на каждую строку подвешивает WebView и кнопки перестают нажиматься.
let renderTimer = null;
function scheduleRender() {
    if (renderTimer) return;
    renderTimer = setTimeout(() => { renderTimer = null; renderLog(); }, 100);
}

function appendLog(line) {
    const last = logLines[logLines.length - 1];
    if (last && last.line === line) { // дедупликация повторов
        last.count++;
    } else {
        logLines.push({ line, cls: classOf(line), count: 1 });
        if (logLines.length > 500) logLines = logLines.slice(-500);
    }
    scheduleRender();
}

function escapeHtml(s) {
    return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function updateTraffic(t) {
    if (!connected) return;
    $('downRate').textContent = fmtBytes(t.downRate) + '/с';
    $('upRate').textContent = fmtBytes(t.upRate) + '/с';
    $('totals').textContent = `↓ ${fmtBytes(t.downTotal)} · ↑ ${fmtBytes(t.upTotal)}`;
}

function wire() {
    ['server', 'password', 'vk', 'workers', 'excludes'].forEach((id) =>
        $(id).addEventListener('input', save));
    $('systemVPN').addEventListener('change', save);

    // профили
    $('profileSel').addEventListener('change', async (e) => {
        const name = e.target.value;
        if (!name) return;
        setFields(await App().LoadProfile(name));
        save();
        $('profileName').value = name;
    });
    $('profileSave').addEventListener('click', async () => {
        const name = ($('profileName').value || $('server').value).trim();
        if (!name) { appendLog('Укажите имя профиля'); return; }
        try { await App().SaveProfile(name, collect()); await refreshProfiles(name); appendLog('Профиль сохранён: ' + name); }
        catch (e) { appendLog('Ошибка профиля: ' + e); }
    });
    $('profileDel').addEventListener('click', async () => {
        const name = $('profileSel').value;
        if (!name) return;
        try { await App().DeleteProfile(name); await refreshProfiles(); appendLog('Профиль удалён: ' + name); }
        catch (e) { appendLog('Ошибка: ' + e); }
    });

    // автозапуск
    $('autostart').addEventListener('change', async (e) => {
        try { await App().SetAutoStart(e.target.checked); }
        catch (err) { appendLog('Автозапуск: ' + err); }
    });

    $('power').addEventListener('click', async () => {
        // подключено ИЛИ подключается → клик отключает/отменяет
        if (stateName !== 'off') { App().Disconnect(); return; }
        setState('connecting');
        const c = collect();
        if (c.systemVPN) {
            App().CheckVPN().then((others) => {
                if (others && others.length) {
                    appendLog('⚠ Активны другие VPN-интерфейсы: ' + others.join(', ') + ' — при проблемах отключите их.');
                }
            }).catch(() => {});
        }
        try {
            const err = await App().Connect(c);
            if (err) { appendLog('Ошибка: ' + err); setState('disconnected'); }
        } catch (e) {
            appendLog('Ошибка: ' + e); setState('disconnected');
        }
    });

    $('diag').addEventListener('click', () => {
        $('logPanel').open = true;
        try { App().Diagnose(); } catch (e) { appendLog('Ошибка диагностики: ' + e); }
    });

    rt().EventsOn('status', setState);
    rt().EventsOn('log', appendLog);
    rt().EventsOn('traffic', updateTraffic);
}

window.addEventListener('DOMContentLoaded', async () => {
    wire();
    await loadSettings();
    await refreshProfiles();
    try { $('autostart').checked = await App().GetAutoStart(); } catch (e) { /* ignore */ }
    $('settings').open = true;
});
