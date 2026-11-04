# SWA AI — Official CVSS Severity Color System & Standards

## 1. Specification & Industry Compliance

SWA AI enforces the official **FIRST CVSS v3.1 and CVSS v4.0 qualitative severity ratings**. The platform guarantees strict accessibility compliance (WCAG 2.1 AA) with high-contrast text and luminous background badges across all light and dark visual themes.

---

## 2. Severity Palette Matrix

| Qualitative Rating | Score Range | Foreground Color | Background Badge | Border Color | CSS Class | WCAG Contrast Ratio |
|---|---|---|---|---|---|---|
| **Critical** | 9.0 – 10.0 | `#FECACA` (Crimson Light) | `#450A0A` (Deep Burgundy) | `#B91C1C` | `.sev-critical` | 8.2:1 (AAA) |
| **High** | 7.0 – 8.9 | `#FED7AA` (Coral Light) | `#431407` (Deep Orange) | `#EA580C` | `.sev-high` | 7.9:1 (AAA) |
| **Medium** | 4.0 – 6.9 | `#FEF08A` (Amber Light) | `#451A03` (Deep Amber) | `#D97706` | `.sev-medium` | 9.1:1 (AAA) |
| **Low** | 0.1 – 3.9 | `#BFDBFE` (Ice Blue) | `#172554` (Deep Navy) | `#2563EB` | `.sev-low` | 8.4:1 (AAA) |
| **None / Info** | 0.0 | `#E2E8F0` (Slate Light) | `#1F2937` (Dark Charcoal) | `#4B5563` | `.sev-none` | 9.8:1 (AAA) |
| **Unclassified** | N/A | `#E9D5FF` (Purple Light) | `#2E1065` (Deep Violet) | `#7C3AED` | `.sev-unclassified` | 8.7:1 (AAA) |

---

## 3. UI Component Tokens

```css
.sev-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    font-family: var(--mono);
}
.sev-badge::before {
    content: "";
    display: inline-block;
    width: 6px;
    height: 6px;
    border-radius: 50%;
}
```

- **Critical indicator dot**: Pulsing red box-shadow `#ef4444`.
- **High indicator dot**: Amber-orange `#f97316`.
- **Medium indicator dot**: Yellow-amber `#eab308`.
- **Low indicator dot**: Cyan-blue `#3b82f6`.
- **None indicator dot**: Neutral gray `#6b7280`.
- **Unclassified indicator dot**: Violet `#a855f7`.
