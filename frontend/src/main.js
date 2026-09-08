import './style.css';

const $ = (id) => document.getElementById(id);
const previewEvents = new Map();
const previewRuntime = { EventsOn: (name, callback) => previewEvents.set(name, callback) };
const previewSettings = {
	server: '', password: '', vkLinks: '', workers: 18,
    systemVPN: true, excludes: '', obfsMode: 'video', turnTransport: 'udp',
};
const previewApp = {
    LoadSettings: async () => previewSettings,
    SaveSettings: async (settings) => Object.assign(previewSettings, settings),
    ListProfiles: async () => [], GetAutoStart: async () => false,
    SetAutoStart: async () => {}, CheckVPN: async () => [], Diagnose: async () => {},
    Platform: async () => 'preview',
    Connect: async () => {
        setTimeout(() => previewEvents.get('status')?.('connected-vpn'), 700);
        return '';
    },
    Disconnect: () => setTimeout(() => previewEvents.get('status')?.('disconnected'), 250),
};
const App = () => window.go?.main?.App || (import.meta.env.DEV ? previewApp : null);
const rt = () => window.runtime || (import.meta.env.DEV ? previewRuntime : null);

let connected = false;
let stateName = 'off'; // off | connecting | connected
let logLines = []; // [{line, cls, count, el}]
let connectedAt = 0;

const LOG_MAX = 500;
// Панель ↔ её кнопка-вкладка. Активная помечается классом .active — переключать
// панели нужно только через showPane().
const PANES = { connectPane: 'tabConnect', settings: 'tabSettings', logPanel: 'tabLog' };

function fmtBytes(n) {
    const f = Number(n) || 0;
    if (f >= 1 << 30) return (f / (1 << 30)).toFixed(2) + ' ГБ';
    if (f >= 1 << 20) return (f / (1 << 20)).toFixed(2) + ' МБ';
    if (f >= 1 << 10) return (f / (1 << 10)).toFixed(1) + ' КБ';
    return f + ' Б';
}

// Ядро округляет -n вниз до кратного 9 и зажимает в [9, 126]: приводим значение
// сразу, чтобы в поле не оставалось числа, которое втихую превратится в другое.
function normalizeWorkers(v) {
    let n = parseInt(v, 10);
    if (!Number.isFinite(n)) n = 18;
    n = Math.min(126, Math.max(9, n));
    return Math.floor(n / 9) * 9;
}

function collect() {
    return {
        server: $('server').value.trim(),
        password: $('password').value.trim(),
        vkLinks: $('vk').value,
        workers: normalizeWorkers($('workers').value),
        systemVPN: true,
        excludes: $('excludes').value,
        obfsMode: $('obfsMode').value === 'video' ? 'video' : 'audio',
        turnTransport: $('turnTransport').value === 'tcp_tls' ? 'tcp_tls' : 'udp',
    };
}

function setFields(s) {
    $('server').value = s.server || '';
    $('password').value = s.password || '';
    $('vk').value = s.vkLinks || '';
    $('workers').value = normalizeWorkers(s.workers);
    $('excludes').value = s.excludes || '';
    $('obfsMode').value = s.obfsMode === 'video' ? 'video' : 'audio';
    $('turnTransport').value = s.turnTransport === 'tcp_tls' ? 'tcp_tls' : 'udp';
}

// Настройки писались на каждое нажатие клавиши: один вызов в Go и одна запись
// файла на символ. Копим изменения и сохраняем пачкой.
let saveTimer = null;
function save() {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => { saveTimer = null; App().SaveSettings(collect()); }, 400);
}

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

// ─── вкладки ───
function syncTabs() {
    for (const [paneId, tabId] of Object.entries(PANES)) {
        $(tabId).setAttribute('aria-selected', $(paneId).classList.contains('active') ? 'true' : 'false');
    }
}

function showPane(paneId) {
    if (activePane() === paneId) return;
    for (const id of Object.keys(PANES)) $(id).classList.toggle('active', id === paneId);
    syncTabs();
    if (paneId !== 'logPanel') return;
    // У скрытого элемента scrollHeight = 0, поэтому автоскролл при рендере не
    // срабатывал. Открыли журнал — показываем хвост, но уже после пересчёта
    // раскладки, иначе scrollHeight ещё старый.
    stickToBottom = true;
    renderLog();
    requestAnimationFrame(() => {
        const log = $('log');
        log.scrollTop = log.scrollHeight;
    });
}

function activePane() {
    return Object.keys(PANES).find((id) => $(id).classList.contains('active')) || 'connectPane';
}

function wirePanes() {
    for (const [paneId, tabId] of Object.entries(PANES)) {
        $(tabId).addEventListener('click', () => showPane(paneId));
    }
    window.addEventListener('keydown', (e) => {
        if (!e.ctrlKey || e.altKey || e.shiftKey) return;
        const idx = ['1', '2', '3'].indexOf(e.key);
        if (idx < 0) return;
        e.preventDefault();
        showPane(Object.keys(PANES)[idx]);
    });
}

function setState(state) {
    const power = $('power'), dot = $('connDot');
    const status = $('status'), sub = $('statusSub');
    let p = 'off', d = 'off', title = 'Отключено', subtitle = 'нажми, чтобы подключиться';
    switch (state) {
        case 'connecting':
            p = d = 'connecting'; title = 'Подключение…'; subtitle = 'устанавливаю туннель · клик — отмена';
            connected = false; break;
        case 'disconnecting':
            p = d = 'connecting'; title = 'Отключение…'; subtitle = 'снимаю маршруты и закрываю туннель';
            connected = false; break;
        case 'connected-vpn':
            p = d = 'connected'; title = 'Защищено'; subtitle = 'системный VPN · весь трафик';
            connected = true; break;
        default:
            connected = false;
            $('downRate').textContent = '—'; $('upRate').textContent = '—';
            $('totals').textContent = '↓ 0 Б · ↑ 0 Б';
    }
    stateName = (state === 'connecting' || state === 'disconnecting') ? state : (connected ? 'connected' : 'off');
    power.dataset.state = p;
    dot.dataset.state = d;
    status.textContent = title;
    sub.textContent = subtitle;
    document.body.dataset.state = (p === 'connected') ? 'connected' : (p === 'connecting' ? 'connecting' : 'off');
    power.setAttribute('aria-label',
        stateName === 'connecting' ? 'Отменить подключение' : (connected ? 'Отключить' : 'Подключить'));

    if (connected) {
        if (!connectedAt) connectedAt = Date.now();
        // Подключились — показываем журнал, но только если пользователь не ушёл
        // сам в настройки.
        if (activePane() === 'connectPane') showPane('logPanel');
    } else {
        connectedAt = 0;
        $('uptime').textContent = '';
    }
    // На disconnected вкладку НЕ переключаем: этот статус приходит и от fail-safe
    // после падения transport/TUN, и увести пользователя с журнала именно в этот
    // момент — значит спрятать причину.
}

function tickUptime() {
    if (!connectedAt) return;
    const s = Math.floor((Date.now() - connectedAt) / 1000);
    const pad = (n) => String(n).padStart(2, '0');
    $('uptime').textContent = `${pad(Math.floor(s / 3600))}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;
}

function classOf(line) {
    if (/ошибк|error|fatal|fail|unreachable/i.test(line)) return 'err';
    if (/warn|не удалось|повтор|retry|⚠|⛔/i.test(line)) return 'warn';
    if (/✅|подключено|защищено|активен|handshake получен|→ OK\b/i.test(line)) return 'ok';
    return '';
}

function lineText(l) { return l.count > 1 ? `${l.line}  ×${l.count}` : l.line; }

// Липкость журнала: следим за прокруткой пользователя, а не вычисляем положение в
// момент отрисовки. При рендере размеры ещё не пересчитаны, и «не у нижнего края»
// ошибочно читалось как «пользователь отлистал вверх» — журнал застревал.
let stickToBottom = true;

// Журнал рисуется по одному узлу на строку и дописывается, а не собирается заново
// через innerHTML: полная перерисовка сбрасывала выделение текста (а журнал у нас
// в первую очередь копируют) и стоила 500 строк каждые 100 мс.
function renderLog() {
    const log = $('log');
    if (!$('logPanel').classList.contains('active')) return; // скрытую панель не рисуем вовсе
    const stick = $('logFollow').checked && stickToBottom;
    for (const l of logLines) {
        if (!l.el) {
            l.el = document.createElement('div');
            l.el.className = l.cls;
            l.el.textContent = lineText(l);
            log.appendChild(l.el);
        } else if (l.dirty) {
            l.el.textContent = lineText(l);
            l.dirty = false;
        }
    }
    if (stick) log.scrollTop = log.scrollHeight;
}

let renderTimer = null;
function scheduleRender() {
    if (renderTimer) return;
    renderTimer = setTimeout(() => { renderTimer = null; renderLog(); }, 100);
}

function appendLog(line) {
    const last = logLines[logLines.length - 1];
    if (last && last.line === line) { // дедупликация повторов
        last.count++;
        last.dirty = true;
    } else {
        logLines.push({ line, cls: classOf(line), count: 1, el: null, dirty: false });
        while (logLines.length > LOG_MAX) {
            const drop = logLines.shift();
            if (drop.el && drop.el.parentNode) drop.el.parentNode.removeChild(drop.el);
        }
    }
    $('logTail').textContent = line;
    scheduleRender();
}

function updateTraffic(t) {
    if (!connected) return;
    $('downRate').textContent = fmtBytes(t.downRate) + '/с';
    $('upRate').textContent = fmtBytes(t.upRate) + '/с';
    $('totals').textContent = `↓ ${fmtBytes(t.downTotal)} · ↑ ${fmtBytes(t.upTotal)}`;
}

async function copyLog() {
    const text = logLines.map(lineText).join('\n');
    try {
        await navigator.clipboard.writeText(text);
        appendLog('Журнал скопирован в буфер обмена');
    } catch (e) {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); appendLog('Журнал скопирован в буфер обмена'); }
        catch (err) { appendLog('Не удалось скопировать журнал: ' + err); }
        document.body.removeChild(ta);
    }
}

function wire() {
    // Подписки — первым делом: если ниже упадёт обработчик из-за опечатки в id,
    // приложение хотя бы продолжит показывать статус и журнал.
    rt().EventsOn('status', setState);
    rt().EventsOn('log', appendLog);
    rt().EventsOn('traffic', updateTraffic);

    wirePanes();
	$('connectionForm').addEventListener('submit', (event) => {
		event.preventDefault();
		$('power').click();
	});
    setInterval(tickUptime, 1000);

    ['server', 'password', 'vk', 'workers', 'excludes'].forEach((id) =>
        $(id).addEventListener('input', save));
    $('workers').addEventListener('change', () => { $('workers').value = normalizeWorkers($('workers').value); save(); });
    $('obfsMode').addEventListener('change', save);
    $('turnTransport').addEventListener('change', save);

    // профили
    $('profileSel').addEventListener('change', async (e) => {
        const name = e.target.value;
        if (!name) return;
        try {
            const s = await App().LoadProfile(name);
            // Go возвращает пустые настройки и когда файл не прочитался: применить
            // их — значит затереть текущие и тут же сохранить пустоту.
            if (!s || (!s.server && !s.password && !s.vkLinks)) {
                appendLog('Профиль не прочитан или пуст: ' + name);
                return;
            }
            setFields(s);
            save();
            $('profileName').value = name;
        } catch (err) { appendLog('Ошибка профиля: ' + err); }
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
        const want = e.target.checked;
        try { await App().SetAutoStart(want); }
        catch (err) {
            e.target.checked = !want; // не оставлять галочку, которая не применилась
            appendLog('Автозапуск: ' + err);
        }
    });

    $('power').addEventListener('click', async () => {
        if (stateName === 'disconnecting') return; // уже отключаемся
        // подключено ИЛИ подключается → клик отключает/отменяет
        if (stateName !== 'off') { setState('disconnecting'); App().Disconnect(); return; }
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
            if (err) {
                appendLog('Ошибка: ' + err);
                // «уже подключено» означает, что туннель жив: сбрасывать GUI в
                // «Отключено» нельзя — кнопка перестанет отключать.
                if (!/уже подключено/i.test(String(err))) setState('disconnected');
            }
        } catch (e) {
            appendLog('Ошибка: ' + e); setState('disconnected');
        }
    });

    $('diag').addEventListener('click', () => {
        showPane('logPanel');
        try { App().Diagnose(); } catch (e) { appendLog('Ошибка диагностики: ' + e); }
    });
    $('logCopy').addEventListener('click', copyLog);
    $('logFollow').addEventListener('change', () => {
        if (!$('logFollow').checked) return;
        stickToBottom = true;
        const log = $('log');
        log.scrollTop = log.scrollHeight;
    });
    // Отлистал вверх — журнал перестаёт прыгать вниз на каждой новой строке;
    // вернулся к нижнему краю — липкость включается снова.
    $('log').addEventListener('scroll', () => {
        const log = $('log');
        stickToBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 6;
    });
}

window.addEventListener('DOMContentLoaded', async () => {
    wire();
    syncTabs();
    await loadSettings();
    await refreshProfiles();
    try { $('autostart').checked = await App().GetAutoStart(); } catch (e) { /* ignore */ }
	try {
		const platform = await App().Platform();
		$('platform').textContent = String(platform || 'desktop').toUpperCase();
		App().UpdateReady?.();
        initUpdater(platform);
		if (platform === 'linux') $('autostart').closest('.toggle').hidden = true;
	} catch (e) { /* ignore */ }
});

// Release notes остаются обычным текстом: HTML/ссылки из release не исполняются.
async function initUpdater(platform) {
    try {
        const v = await App().VersionInfo();
        $('versionInfo').textContent = `GUI ${v.desktop} · Core ${v.core}\n${v.compatibility}`;
    } catch (e) { $('versionInfo').textContent = 'Версия недоступна'; }
    if (platform !== 'windows') return;
    $('updateControls').hidden = false;
    try { $('lastUpdateResult').textContent = await App().LastUpdateResult(); } catch (e) { /* отдельный журнал необязателен */ }
    const check = async () => {
        $('checkUpdate').disabled = true;
        $('installUpdate').hidden = true;
        $('updateStatus').textContent = 'Проверка GitHub…';
        try {
            const c = await App().CheckForUpdate();
            $('updateStatus').textContent = c ? `Доступна ${c.version} (GUI + core). ${c.compatibility}` : 'Установлена актуальная стабильная версия.';
            $('updateNotes').textContent = c?.notes || '';
            $('installUpdate').hidden = !c;
        } catch (e) { $('updateStatus').textContent = `Проверка не выполнена: ${e}`; }
        finally { $('checkUpdate').disabled = false; }
    };
    $('checkUpdate').onclick = check;
    $('cancelUpdate').onclick = () => App().CancelUpdate();
    rt().EventsOn('update-progress', p => {
        $('updateProgress').value = p.total ? 100 * p.received / p.total : 0;
        $('updateStatus').textContent = p.received >= p.total ? 'Проверка bundle, остановка VPN и перезапуск…' : `Загрузка: ${fmtBytes(p.received)} / ${fmtBytes(p.total)}`;
        $('cancelUpdate').hidden = p.received >= p.total;
    });
    $('installUpdate').onclick = async () => {
        // Нажатие этой явно подписанной кнопки — согласие на остановку VPN/установку.
        $('installUpdate').disabled = true; $('checkUpdate').disabled = true;
        $('updateProgress').hidden = false; $('updateProgress').value = 0;
        $('cancelUpdate').hidden = false;
        try {
            if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
            await App().SaveSettings(collect());
            await App().InstallUpdate();
        }
        catch (e) { $('updateStatus').textContent = `Обновление не установлено: ${e}`; }
        finally {
            $('installUpdate').disabled = false; $('checkUpdate').disabled = false;
            $('cancelUpdate').hidden = true; $('updateProgress').hidden = true;
        }
    };
    await check();
}
