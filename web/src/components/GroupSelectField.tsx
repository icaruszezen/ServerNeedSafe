import React, { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Check, ChevronDown, Folder, FolderPlus, X } from 'lucide-react';

const useIsomorphicLayoutEffect = typeof window !== 'undefined' ? useLayoutEffect : useEffect;

export interface GroupDropdownItem {
  kind: 'existing' | 'create';
  value: string;
}

export interface GroupDropdownState {
  allGroups: string[];
  matchedGroups: string[];
  canCreateNew: boolean;
  newGroupValue: string;
  items: GroupDropdownItem[];
}

export interface RectLike {
  top: number;
  bottom: number;
  left: number;
  width: number;
  height: number;
}

export interface MenuPositionResult {
  hiddenByScroll: boolean;
  openUpward: boolean;
  style: React.CSSProperties;
}

const HIDDEN_MENU_STYLE: React.CSSProperties = {
  position: 'fixed',
  top: 0,
  left: 0,
  visibility: 'hidden',
};

/**
 * Deduplicates and trims group names while preserving original order.
 */
export function normalizeGroupOptions(groups: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of groups) {
    const trimmed = (raw || '').trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

/**
 * Computes the visible options for the server group combobox.
 *
 * Key invariant: when `isFiltering` is false (e.g. user opened the dropdown while a default
 * group like "生产环境" is already pre-filled), ALL existing groups are shown so the user
 * can switch groups in a single click without deleting the pre-filled text first.
 */
export function buildGroupDropdownState(
  groups: readonly string[],
  value: string,
  isFiltering: boolean
): GroupDropdownState {
  const allGroups = normalizeGroupOptions(groups);
  const trimmed = value.trim();
  const queryLower = trimmed.toLowerCase();

  const matchedGroups =
    !isFiltering || !queryLower
      ? allGroups
      : allGroups.filter((g) => g.toLowerCase().includes(queryLower));

  const canCreateNew = trimmed.length > 0 && !allGroups.includes(trimmed);
  const items: GroupDropdownItem[] = matchedGroups.map((g) => ({
    kind: 'existing',
    value: g,
  }));
  if (canCreateNew) {
    items.push({ kind: 'create', value: trimmed });
  }

  return {
    allGroups,
    matchedGroups,
    canCreateNew,
    newGroupValue: canCreateNew ? trimmed : '',
    items,
  };
}

/**
 * Computes viewport-safe fixed coordinates for the floating dropdown menu.
 * Automatically flips upward when space below is tight, clamps width/left within the viewport
 * to prevent horizontal overflow, and flags dismissal if the anchor scrolled outside its modal body.
 */
export function computeGroupMenuPosition(
  anchorRect: RectLike,
  scrollParentRect: Pick<RectLike, 'top' | 'bottom'> | null,
  viewport: { width: number; height: number }
): MenuPositionResult {
  if (scrollParentRect) {
    if (
      anchorRect.bottom <= scrollParentRect.top ||
      anchorRect.top >= scrollParentRect.bottom
    ) {
      return {
        hiddenByScroll: true,
        openUpward: false,
        style: HIDDEN_MENU_STYLE,
      };
    }
  }

  const gap = 4;
  const margin = 8;
  const preferredMaxH = 248;

  const spaceBelow = viewport.height - anchorRect.bottom - margin - gap;
  const spaceAbove = anchorRect.top - margin - gap;
  const openUpward = spaceBelow < 160 && spaceAbove > spaceBelow;
  const availableVertical = Math.floor(openUpward ? spaceAbove : spaceBelow);
  const maxHeight = Math.max(96, Math.min(preferredMaxH, availableVertical));

  const maxAllowedWidth = Math.max(120, viewport.width - margin * 2);
  const width = Math.min(Math.max(anchorRect.width, 160), maxAllowedWidth);
  const left = Math.max(margin, Math.min(anchorRect.left, viewport.width - margin - width));

  return {
    hiddenByScroll: false,
    openUpward,
    style: openUpward
      ? {
          position: 'fixed',
          left,
          bottom: Math.max(margin, viewport.height - anchorRect.top + gap),
          width,
          maxHeight,
        }
      : {
          position: 'fixed',
          left,
          top: Math.max(margin, anchorRect.bottom + gap),
          width,
          maxHeight,
        },
  };
}

export interface GroupSelectFieldProps {
  id?: string;
  value: string;
  groups: string[];
  groupCounts?: Record<string, number>;
  placeholder?: string;
  onChange: (nextGroup: string) => void;
}

export const GroupSelectField: React.FC<GroupSelectFieldProps> = ({
  id = 'srv-group-input',
  value,
  groups,
  groupCounts,
  placeholder = '选择已有分组，或输入新分组名称',
  onChange,
}) => {
  const reactId = useId();
  const listboxId = id ? `${id}-listbox` : `group-listbox-${reactId}`;

  const containerRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const optionRefs = useRef<(HTMLButtonElement | null)[]>([]);
  // Guards against mobile WebKit/iOS Safari firing input blur before option/button click completes
  const pointerDownInsideRef = useRef(false);

  const [open, setOpen] = useState(false);
  const [isFiltering, setIsFiltering] = useState(false);
  const [activeIndex, setActiveIndex] = useState<number>(-1);
  const [menuStyle, setMenuStyle] = useState<React.CSSProperties>(HIDDEN_MENU_STYLE);

  const dropdown = useMemo(
    () => buildGroupDropdownState(groups, value, isFiltering),
    [groups, value, isFiltering]
  );

  // Trim stale refs when filtered option list shrinks
  optionRefs.current.length = dropdown.items.length;

  const selectedTrimmed = value.trim();
  const showClear = open && value.length > 0;

  const updateMenuPosition = useCallback(() => {
    const anchor = containerRef.current;
    if (!anchor || typeof window === 'undefined') return;

    const rect = anchor.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return;

    const scrollParent = anchor.closest('.modal-body');
    const parentRect = scrollParent ? scrollParent.getBoundingClientRect() : null;

    const result = computeGroupMenuPosition(rect, parentRect, {
      width: window.innerWidth,
      height: window.innerHeight,
    });
    if (result.hiddenByScroll) {
      setOpen(false);
      setIsFiltering(false);
      return;
    }
    setMenuStyle(result.style);
  }, []);

  const openDropdownAll = useCallback(() => {
    setIsFiltering(false);
    setOpen(true);
    const allItems = buildGroupDropdownState(groups, value, false).items;
    const currentIdx = allItems.findIndex(
      (item) => item.kind === 'existing' && item.value === value.trim()
    );
    setActiveIndex(currentIdx >= 0 ? currentIdx : allItems.length > 0 ? 0 : -1);
  }, [groups, value]);

  const closeDropdown = useCallback(() => {
    pointerDownInsideRef.current = false;
    setOpen(false);
    setIsFiltering(false);
  }, []);

  const handleSelect = useCallback(
    (nextGroup: string) => {
      onChange(nextGroup);
      closeDropdown();
    },
    [onChange, closeDropdown]
  );

  // Sync menu position on open, resize, and ancestor scroll
  useIsomorphicLayoutEffect(() => {
    if (!open) return;
    updateMenuPosition();

    const onResize = () => updateMenuPosition();
    const onScroll = (e: Event) => {
      // Ignore scrolling inside the dropdown list itself
      if (e.target instanceof Node && menuRef.current?.contains(e.target)) {
        return;
      }
      updateMenuPosition();
    };

    window.addEventListener('resize', onResize);
    window.addEventListener('scroll', onScroll, true);
    return () => {
      window.removeEventListener('resize', onResize);
      window.removeEventListener('scroll', onScroll, true);
    };
  }, [open, updateMenuPosition]);

  // Outside pointer dismissal & release tracking for touch devices
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: MouseEvent | PointerEvent) => {
      const target = e.target;
      if (!(target instanceof Node)) return;
      if (containerRef.current?.contains(target) || menuRef.current?.contains(target)) {
        pointerDownInsideRef.current = true;
        return;
      }
      closeDropdown();
    };
    const onPointerRelease = () => {
      // Release on next macrotask so any blur fired during touch release still sees the guard
      window.setTimeout(() => {
        pointerDownInsideRef.current = false;
      }, 0);
    };
    document.addEventListener('pointerdown', onPointerDown, true);
    window.addEventListener('pointerup', onPointerRelease, true);
    window.addEventListener('pointercancel', onPointerRelease, true);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown, true);
      window.removeEventListener('pointerup', onPointerRelease, true);
      window.removeEventListener('pointercancel', onPointerRelease, true);
    };
  }, [open, closeDropdown]);

  // Keep activeIndex in bounds when items change
  useEffect(() => {
    if (!open) return;
    if (dropdown.items.length === 0) {
      setActiveIndex(-1);
    } else if (activeIndex >= dropdown.items.length) {
      setActiveIndex(0);
    }
  }, [open, dropdown.items.length, activeIndex]);

  // Keep keyboard-highlighted option visible inside scrollable menu
  useEffect(() => {
    if (!open || activeIndex < 0) return;
    const el = optionRefs.current[activeIndex];
    if (el && typeof el.scrollIntoView === 'function') {
      el.scrollIntoView({ block: 'nearest' });
    }
  }, [open, activeIndex]);

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    // Never intercept IME composition keys (e.g. confirming Chinese Pinyin candidates)
    if (e.nativeEvent.isComposing || e.keyCode === 229) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (!open) {
        openDropdownAll();
        return;
      }
      if (dropdown.items.length > 0) {
        setActiveIndex((prev) => (prev + 1) % dropdown.items.length);
      }
      return;
    }

    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!open) {
        openDropdownAll();
        return;
      }
      if (dropdown.items.length > 0) {
        setActiveIndex((prev) => (prev <= 0 ? dropdown.items.length - 1 : prev - 1));
      }
      return;
    }

    if (e.key === 'Enter' && open) {
      e.preventDefault();
      if (dropdown.items.length > 0) {
        const idx = activeIndex >= 0 && activeIndex < dropdown.items.length ? activeIndex : 0;
        handleSelect(dropdown.items[idx].value);
      } else {
        closeDropdown();
      }
      return;
    }

    if (e.key === 'Escape' && open) {
      e.preventDefault();
      e.stopPropagation();
      closeDropdown();
    }
  };

  const handleInputBlur = (e: React.FocusEvent<HTMLInputElement>) => {
    if (pointerDownInsideRef.current) {
      return;
    }
    const nextFocus = e.relatedTarget;
    if (
      nextFocus instanceof Node &&
      (containerRef.current?.contains(nextFocus) || menuRef.current?.contains(nextFocus))
    ) {
      return;
    }
    closeDropdown();
  };

  const handleToggleClick = () => {
    if (open) {
      closeDropdown();
      return;
    }
    openDropdownAll();
    inputRef.current?.focus();
  };

  const handleClearClick = () => {
    onChange('');
    setIsFiltering(false);
    setOpen(true);
    setActiveIndex(dropdown.allGroups.length > 0 ? 0 : -1);
    inputRef.current?.focus();
  };

  const activeOptionId =
    open && activeIndex >= 0 && activeIndex < dropdown.items.length
      ? `${listboxId}-opt-${activeIndex}`
      : undefined;

  const menuPortal =
    open && typeof document !== 'undefined'
      ? createPortal(
          <div
            ref={menuRef}
            id={listboxId}
            role="listbox"
            aria-label="服务器分组列表"
            className="group-combobox-menu"
            style={menuStyle}
            onPointerDown={() => {
              pointerDownInsideRef.current = true;
            }}
            onMouseDown={(e) => {
              // Keep input focus intact when clicking options or dragging menu scrollbar
              pointerDownInsideRef.current = true;
              e.preventDefault();
            }}
          >
            {dropdown.items.length === 0 ? (
              <div className="group-combobox-empty">
                暂无已有分组，直接输入名称即可创建
              </div>
            ) : (
              dropdown.items.map((item, idx) => {
                const isSelected =
                  item.kind === 'existing' && item.value === selectedTrimmed;
                const isActive = idx === activeIndex;
                const count =
                  item.kind === 'existing' && groupCounts
                    ? (groupCounts[item.value] ?? 0)
                    : undefined;
                const showCreateDivider =
                  item.kind === 'create' && dropdown.matchedGroups.length > 0;

                return (
                  <button
                    key={`${item.kind}:${item.value}`}
                    id={`${listboxId}-opt-${idx}`}
                    ref={(el) => {
                      optionRefs.current[idx] = el;
                    }}
                    type="button"
                    role="option"
                    aria-selected={isSelected}
                    className={`group-combobox-option${isSelected ? ' selected' : ''}${
                      isActive ? ' active' : ''
                    }${item.kind === 'create' ? ' create' : ''}${
                      showCreateDivider ? ' with-divider' : ''
                    }`}
                    title={
                      item.kind === 'create'
                        ? `使用新分组「${item.value}」`
                        : item.value
                    }
                    onMouseEnter={() => setActiveIndex(idx)}
                    onClick={() => handleSelect(item.value)}
                  >
                    <span className="group-combobox-option-label">
                      {item.kind === 'create' ? (
                        <FolderPlus size={13.5} className="group-combobox-option-icon" />
                      ) : (
                        <Folder size={13.5} className="group-combobox-option-icon" />
                      )}
                      <span className="group-combobox-option-text">
                        {item.kind === 'create'
                          ? `使用新分组「${item.value}」`
                          : item.value}
                      </span>
                    </span>
                    <span className="group-combobox-option-meta">
                      {item.kind === 'create' ? (
                        <span className="group-combobox-create-badge">新建</span>
                      ) : (
                        <>
                          {typeof count === 'number' && (
                            <span className="group-combobox-count tabular">
                              {count} 台
                            </span>
                          )}
                          {isSelected && (
                            <Check size={14} className="group-combobox-check" />
                          )}
                        </>
                      )}
                    </span>
                  </button>
                );
              })
            )}
          </div>,
          document.body
        )
      : null;

  return (
    <div className={`group-combobox${open ? ' open' : ''}`} ref={containerRef}>
      <input
        ref={inputRef}
        id={id}
        type="text"
        className={`input group-combobox-input${showClear ? ' has-clear' : ''}`}
        value={value}
        placeholder={placeholder}
        autoComplete="off"
        role="combobox"
        aria-autocomplete="list"
        aria-expanded={open}
        aria-controls={listboxId}
        aria-activedescendant={activeOptionId}
        onFocus={() => {
          if (!open) {
            openDropdownAll();
          }
        }}
        onClick={() => {
          if (!open) {
            openDropdownAll();
          }
        }}
        onChange={(e) => {
          const next = e.target.value;
          onChange(next);
          setIsFiltering(true);
          setOpen(true);
          setActiveIndex(0);
        }}
        onKeyDown={handleInputKeyDown}
        onBlur={handleInputBlur}
      />
      <div className="group-combobox-actions">
        {showClear && (
          <button
            type="button"
            id={id ? `${id}-clear` : undefined}
            className="group-combobox-clear"
            tabIndex={-1}
            aria-label="清空分组输入"
            title="清空"
            onPointerDown={() => {
              pointerDownInsideRef.current = true;
            }}
            onMouseDown={(e) => {
              pointerDownInsideRef.current = true;
              e.preventDefault();
            }}
            onClick={handleClearClick}
          >
            <X size={13.5} />
          </button>
        )}
        <button
          type="button"
          id={id ? `${id}-toggle` : undefined}
          className="group-combobox-toggle"
          tabIndex={-1}
          aria-label={open ? '收起分组下拉列表' : '展开分组下拉列表'}
          aria-expanded={open}
          onPointerDown={() => {
            pointerDownInsideRef.current = true;
          }}
          onMouseDown={(e) => {
            pointerDownInsideRef.current = true;
            e.preventDefault();
          }}
          onClick={handleToggleClick}
        >
          <ChevronDown size={15} className="group-combobox-chevron" />
        </button>
      </div>
      {menuPortal}
    </div>
  );
};
