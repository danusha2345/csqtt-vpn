import test from 'node:test';
import assert from 'node:assert/strict';
import { replaceTrafficLogLine } from './traffic-log.mjs';

const stats = (n) => `[client] [СТАТИСТИКА] Активных: 18 | Трафик: ${n}.00 МБ`;

test('traffic updates retain one row and its DOM node across intervening messages', () => {
    const element = {};
    const row = { line: stats(1), count: 4, el: element, dirty: false };
    const error = { line: '[client] [СЕТЬ][RETRY] Ошибка подключения', count: 1 };
    const entries = [row, error];
    for (let n = 2; n < 100; n++) assert.equal(replaceTrafficLogLine(entries, stats(n)), true);
    assert.equal(entries.length, 2);
    assert.equal(row.el, element);
    assert.equal(row.line, stats(99));
    assert.equal(row.count, 1);
    assert.equal(row.dirty, true);
    assert.equal(entries[1], error);
});

test('first summary and a summary evicted by the log limit can be appended normally', () => {
    assert.equal(replaceTrafficLogLine([], stats(1)), false);
    assert.equal(replaceTrafficLogLine([{ line: 'Подключено' }], stats(2)), false);
});

test('network errors and arbitrary messages never replace statistics', () => {
    const entries = [{ line: stats(1) }];
    for (const message of ['[СЕТЬ][RETRY] Ошибка', 'Трафик: ошибка', 'Подключено']) {
        assert.equal(replaceTrafficLogLine(entries, message), false);
    }
    assert.equal(entries[0].line, stats(1));
});

test('Android-style summary and repeated values also update in place', () => {
    const line = '[СЕТЬ] Активных: 0 | Трафик: 1,25 МБ';
    const row = { line, count: 1 };
    assert.equal(replaceTrafficLogLine([row], line), true);
    assert.equal(row.count, 1);
    assert.equal(row.dirty, true);
});

test('actual appendLog/renderLog update the existing DOM row and preserve errors', async () => {
    const { readFileSync } = await import('node:fs');
    const { createContext, runInContext } = await import('node:vm');
    const children = [];
    const log = {
        appendChild(el) { children.push(el); el.parentNode = this; },
        removeChild(el) { children.splice(children.indexOf(el), 1); },
        scrollHeight: 100, scrollTop: 0,
    };
    const elements = { log, logPanel: { classList: { contains: () => true } },
        logFollow: { checked: true }, logTail: { textContent: '' } };
    const context = createContext({ replaceTrafficLogLine,
        document: { getElementById: (id) => elements[id], createElement: () => ({}) },
        window: { addEventListener() {} }, setTimeout: () => 1 });
    const source = readFileSync(new URL('./main.js', import.meta.url), 'utf8')
        .replace(/^import .*;\r?\n/gm, '').replaceAll('import.meta.env.DEV', 'false');
    runInContext(source, context);
    // Windows checkout uses CRLF; imports must be removed in both formats.
    const crlf = readFileSync(new URL('./main.js', import.meta.url), 'utf8')
        .replace(/\r?\n/g, '\r\n')
        .replace(/^import .*;\r?\n/gm, '').replaceAll('import.meta.env.DEV', 'false');
    runInContext(crlf, createContext({ replaceTrafficLogLine,
        document: { getElementById: (id) => elements[id], createElement: () => ({}) },
        window: { addEventListener() {} }, setTimeout: () => 1 }));
    runInContext(`appendLog(${JSON.stringify(stats(1))}); renderLog();`, context);
    const original = children[0];
    runInContext(`appendLog('Ошибка тестовая'); appendLog(${JSON.stringify(stats(2))}); renderLog();`, context);
    assert.equal(children.length, 2);
    assert.equal(children[0], original);
    assert.equal(original.textContent, stats(2));
    assert.equal(children[1].textContent, 'Ошибка тестовая');
});
