import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, '..');

test('GroupSelectField state logic, portal positioning, and SSR markup behave cleanly', async () => {
  const vite = await createServer({
    root: webDir,
    logLevel: 'silent',
    server: { middlewareMode: true },
    appType: 'custom',
  });

  try {
    const {
      normalizeGroupOptions,
      buildGroupDropdownState,
      computeGroupMenuPosition,
      GroupSelectField,
    } = await vite.ssrLoadModule('/src/components/GroupSelectField.tsx');

    // 1. normalizeGroupOptions trims, drops blanks, deduplicates, and preserves order
    assert.deepEqual(
      normalizeGroupOptions(['  生产环境 ', '', '核心数据库', '生产环境', '  ', '测试与预发']),
      ['生产环境', '核心数据库', '测试与预发']
    );

    const defaults = ['生产环境', '核心数据库', '测试与预发', '边缘与网关'];

    // 2. Core regression fix: when modal pre-fills "生产环境" and dropdown opens without typing
    //    (isFiltering=false), ALL groups must remain visible — not filtered down to only "生产环境".
    const initialOpen = buildGroupDropdownState(defaults, '生产环境', false);
    assert.deepEqual(initialOpen.matchedGroups, defaults);
    assert.equal(initialOpen.canCreateNew, false);
    assert.deepEqual(
      initialOpen.items,
      defaults.map((value) => ({ kind: 'existing', value }))
    );

    // 3. Typing a substring filters case-insensitively and offers a create option when not an exact match
    const filtered = buildGroupDropdownState(
      [...defaults, 'HK-Edge-Nodes'],
      'edge',
      true
    );
    assert.deepEqual(filtered.matchedGroups, ['HK-Edge-Nodes']);
    assert.equal(filtered.canCreateNew, true);
    assert.equal(filtered.newGroupValue, 'edge');
    assert.deepEqual(filtered.items, [
      { kind: 'existing', value: 'HK-Edge-Nodes' },
      { kind: 'create', value: 'edge' },
    ]);

    // 4. Typing a brand-new Chinese group name offers create option directly
    const brandNew = buildGroupDropdownState(defaults, '  海外 GPU 算力池  ', true);
    assert.deepEqual(brandNew.matchedGroups, []);
    assert.equal(brandNew.canCreateNew, true);
    assert.equal(brandNew.newGroupValue, '海外 GPU 算力池');
    assert.deepEqual(brandNew.items, [{ kind: 'create', value: '海外 GPU 算力池' }]);

    // 5. Exact match (even with surrounding whitespace) does NOT duplicate a create option
    const exact = buildGroupDropdownState(defaults, ' 核心数据库 ', true);
    assert.deepEqual(exact.matchedGroups, ['核心数据库']);
    assert.equal(exact.canCreateNew, false);
    assert.deepEqual(exact.items, [{ kind: 'existing', value: '核心数据库' }]);

    // 6. Clearing input while filtering shows all groups again without create option
    const cleared = buildGroupDropdownState(defaults, '', true);
    assert.deepEqual(cleared.matchedGroups, defaults);
    assert.equal(cleared.canCreateNew, false);

    // 7. Empty existing groups + pre-filled default still exposes create option
    const noExisting = buildGroupDropdownState([], '生产环境', false);
    assert.deepEqual(noExisting.matchedGroups, []);
    assert.equal(noExisting.canCreateNew, true);
    assert.deepEqual(noExisting.items, [{ kind: 'create', value: '生产环境' }]);

    // 8. computeGroupMenuPosition opens downward with exact anchor width on desktop
    const desktopPos = computeGroupMenuPosition(
      { top: 180, bottom: 216, left: 620, width: 340, height: 36 },
      { top: 120, bottom: 760 },
      { width: 1440, height: 900 }
    );
    assert.equal(desktopPos.hiddenByScroll, false);
    assert.equal(desktopPos.openUpward, false);
    assert.equal(desktopPos.style.position, 'fixed');
    assert.equal(desktopPos.style.left, 620);
    assert.equal(desktopPos.style.top, 220);
    assert.equal(desktopPos.style.width, 340);
    assert.equal(desktopPos.style.maxHeight, 248);

    // 9. computeGroupMenuPosition flips upward when space below is tight (e.g. mobile landscape)
    const flippedPos = computeGroupMenuPosition(
      { top: 300, bottom: 340, left: 16, width: 358, height: 40 },
      { top: 50, bottom: 380 },
      { width: 390, height: 420 }
    );
    assert.equal(flippedPos.hiddenByScroll, false);
    assert.equal(flippedPos.openUpward, true);
    assert.equal(flippedPos.style.bottom, 124);
    assert.equal(flippedPos.style.top, undefined);

    // 10. computeGroupMenuPosition clamps horizontal bounds on narrow 320px viewports
    const narrowPos = computeGroupMenuPosition(
      { top: 140, bottom: 180, left: 20, width: 360, height: 40 },
      { top: 60, bottom: 520 },
      { width: 320, height: 568 }
    );
    assert.equal(narrowPos.hiddenByScroll, false);
    assert.equal(narrowPos.style.width, 304);
    assert.equal(narrowPos.style.left, 8);

    // 11. computeGroupMenuPosition dismisses cleanly if anchor scrolled outside modal-body
    const scrolledOut = computeGroupMenuPosition(
      { top: 40, bottom: 76, left: 620, width: 340, height: 36 },
      { top: 100, bottom: 760 },
      { width: 1440, height: 900 }
    );
    assert.equal(scrolledOut.hiddenByScroll, true);

    // 12. SSR render outputs accessible combobox input + toggle button and NEVER uses native <datalist>
    const html = renderToStaticMarkup(
      React.createElement(GroupSelectField, {
        id: 'srv-group-input',
        value: '生产环境',
        groups: defaults,
        groupCounts: { 生产环境: 3, 核心数据库: 1 },
        onChange: () => {},
      })
    );
    assert.ok(html.includes('id="srv-group-input"'), 'preserves #srv-group-input id');
    assert.ok(html.includes('role="combobox"'), 'renders combobox ARIA role');
    assert.ok(html.includes('aria-expanded="false"'), 'starts collapsed');
    assert.ok(html.includes('id="srv-group-input-toggle"'), 'renders dropdown chevron toggle button');
    assert.ok(html.includes('value="生产环境"'), 'reflects pre-filled default group');
    assert.equal(html.includes('<datalist'), false, 'must not render native <datalist>');
  } finally {
    await vite.close();
  }
});
