---
name: Analog-Digital Instrument Console
colors:
  surface: '#fff8ef'
  surface-dim: '#dfd9cf'
  surface-bright: '#fff8ef'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f9f3e8'
  surface-container: '#f4ede3'
  surface-container-high: '#eee7dd'
  surface-container-highest: '#e8e2d7'
  on-surface: '#1e1b15'
  on-surface-variant: '#5b4038'
  inverse-surface: '#333029'
  inverse-on-surface: '#f6f0e5'
  outline: '#8f7067'
  outline-variant: '#e4beb3'
  surface-tint: '#ae3200'
  primary: '#ae3200'
  on-primary: '#ffffff'
  primary-container: '#ff5a1f'
  on-primary-container: '#541400'
  inverse-primary: '#ffb59e'
  secondary: '#5c614d'
  on-secondary: '#ffffff'
  secondary-container: '#e0e5cc'
  on-secondary-container: '#626753'
  tertiary: '#615e56'
  on-tertiary: '#ffffff'
  tertiary-container: '#969289'
  on-tertiary-container: '#2d2b25'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#ffdbd0'
  primary-fixed-dim: '#ffb59e'
  on-primary-fixed: '#3a0b00'
  on-primary-fixed-variant: '#852400'
  secondary-fixed: '#e0e5cc'
  secondary-fixed-dim: '#c4c9b1'
  on-secondary-fixed: '#191d0e'
  on-secondary-fixed-variant: '#444937'
  tertiary-fixed: '#e7e2d8'
  tertiary-fixed-dim: '#cbc6bc'
  on-tertiary-fixed: '#1d1c15'
  on-tertiary-fixed-variant: '#49473f'
  background: '#fff8ef'
  on-background: '#1e1b15'
  surface-variant: '#e8e2d7'
typography:
  display-lg:
    fontFamily: Bricolage Grotesque
    fontSize: 44px
    fontWeight: '800'
    lineHeight: 52px
    letterSpacing: -0.02em
  display-lg-mobile:
    fontFamily: Bricolage Grotesque
    fontSize: 32px
    fontWeight: '800'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-lg:
    fontFamily: Bricolage Grotesque
    fontSize: 28px
    fontWeight: '700'
    lineHeight: 36px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Bricolage Grotesque
    fontSize: 22px
    fontWeight: '700'
    lineHeight: 28px
  headline-sm:
    fontFamily: Bricolage Grotesque
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  body-lg:
    fontFamily: IBM Plex Sans
    fontSize: 16px
    fontWeight: '500'
    lineHeight: 24px
  body-md:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: IBM Plex Sans
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  telemetry-lg:
    fontFamily: JetBrains Mono
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 30px
    letterSpacing: 0.02em
  telemetry-md:
    fontFamily: JetBrains Mono
    fontSize: 16px
    fontWeight: '600'
    lineHeight: 22px
    letterSpacing: 0.04em
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.10em
  label-micro:
    fontFamily: JetBrains Mono
    fontSize: 9px
    fontWeight: '600'
    lineHeight: 12px
    letterSpacing: 0.12em
spacing:
  gutter: 1.25rem
  gutter-mobile: 0.75rem
  margin: 2rem
  margin-mobile: 1rem
  space-xxs: 0.125rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2.25rem
  space-xxl: 3rem
---

## Brand & Style

This design system channels the precision, tactile weight, and mechanical certainty of mid-century industrial test benches, synthesizer racks, and laboratory instrumentation consoles. It balances raw physical authenticity with the sharp efficiency of modern telemetry tools. The user experience is immediate, visceral, and unapologetically physical—every interaction produces visual displacement reminiscent of machined metal, toggle switches, and stamped phenolic plates.

The audience encompasses engineers, sound designers, telemetry operators, and systems analysts who demand immediate legibility, zero ambiguity, and high ergonomic density. The system strictly avoids decorative skeuomorphic gradients, glass distortion, or atmospheric blurs. Instead, it relies on bold ink-drafted geometry, mechanical offsets, strict tabular measurements, and hard tactile feedback loops.

## Colors

The palette reproduces physical print surfaces, stamped metal faceplates, and high-visibility industrial markings:

- **Ground / Canvas (`#EFEBE3`)**: Warm fibrous base paper, providing organic warmth under stacked technical panels.
- **Panel Surface (`#F7F4EE`)**: High-contrast cream paper plate used for elevated modules, cards, and reading zones.
- **Border & Solid Ink (`#17150F`)**: Deep carbon ink used for structural containment lines, hard stamp shadows, typography, and unlit indicators.
- **Signal Orange (`#FF5A1F`)**: Primary high-visibility accent reserved strictly for active states, key telemetry readouts, selected toggles, and primary execution points.
- **Muted Olive (`#6B705C`)**: Secondary accent for passive operational status, calibrator ticks, reference grids, and technical sub-labels.
- **Warm Slate (`#9A968D`)**: Mid-tone tint for inactive scale indices, disabled paths, and tertiary boundaries.
- **Light Tint (`#E6E1D6`)**: Recessed channel tracks, inactive button cavities, and sunken bay fills.

Never introduce opacity ramps or translucent washes on structural boundaries; color steps are flat, discrete, and high in ink density.

## Typography

Typographic roles adhere to two distinct functional tracks:

1. **Section Framing & Display**: Rendered in **Bricolage Grotesque** with heavy weights (600–800). Features a mechanical, compressed punch evoking embossed metal nameplates, warning stamps, and industrial machine chassis headers.
2. **Telemetry, Controls & Micro Labels**: Rendered in **JetBrains Mono** with tabular numerals enforced across all metrics. All micro tags, state flags, and unit markings must be rendered in strict uppercase with expanded tracking (0.08em to 0.12em) to emulate stamped military-spec faceplates.
3. **Descriptive Run-in Text**: Handled by **IBM Plex Sans** for neutral, utilitarian legibility in documentation panes or log windows.

## Layout & Spacing

The layout is structured as a modular instrumentation rack. Panels snap to a 12-column rigid framework on desktop screens, consolidating into 6 columns on tablet devices, and a single vertical bay stack on mobile viewports.

- **Bay Separation**: Major functional modules are encased in discrete panel chassis cards separated by `gutter` (20px / 1.25rem).
- **Internal Cluster Density**: Control clusters (rotary knobs, toggle switches, digital indicators) rely on `space-sm` (8px) and `space-md` (16px) gaps to preserve high density and operational reach.
- **Chassis Margins**: Outer console frame uses `margin` (32px / 2rem), contracting to `margin-mobile` (16px / 1rem) at `< 768px` viewports.
- **Alignment**: Every panel boundary, dividing rule, and bezel track aligns to a strict 4px sub-grid.

## Elevation & Depth

Depth is purely mechanical and physical, executed via high-contrast hard offset projections:

- **Resting Elevation**: All interactable and elevated panels project a hard solid shadow: `box-shadow: 4px 4px 0px #17150F`. Under no circumstances should soft blur radii (`blur > 0`) or diffuse ambient alphas be used.
- **Hover State**: Slightly amplified mechanical offset: `box-shadow: 5px 5px 0px #17150F` accompanied by `transform: translate(-1px, -1px)`.
- **Active / Pressed State**: Depressed into the chassis bed: `box-shadow: 0px 0px 0px #17150F` accompanied by `transform: translate(4px, 4px)`.
- **Recessed Channels & Bays**: Elements representing cutouts, linear slider wells, or digital LED counters use an inset mechanical border: `box-shadow: inset 2px 2px 0px #17150F` over background `#E6E1D6`.
- **Structural Inking**: Every surface-level boundary must have a solid border of `1.5px solid #17150F`.

## Shapes

The geometric vernacular is hard-edged and machined:

- **Base Radius**: `0px` (Strictly Sharp). Buttons, switch plates, displays, and badges are crisp 90-degree rectangles.
- **Panel Chassis Exception**: Main perimeter bay modules may use a maximum corner radius of `2px` to subtly suggest stamped sheet metal edges, though interior contents, sub-bays, and inputs remain strictly `0px`.
- **Rotary Elements**: Dials and potentiometer knobs use true circles (`border-radius: 50%`) with high-contrast radial index lines and tick marks spaced at 30-degree or 45-degree intervals.

## Components

### Buttons
- **Primary Action**: Solid `#FF5A1F` fill, 1.5px `#17150F` border, `#17150F` text in bold uppercase mono, resting shadow `4px 4px 0px #17150F`. Active state snaps to `translate(4px, 4px)` with zero shadow.
- **Secondary / Utilitarian**: Surface `#F7F4EE` fill, 1.5px `#17150F` border, text `#17150F`.
- **Mechanical Rocker Toggle**: Stamped two-position physical switch divided by a 1.5px ink line. The active side fills with `#17150F` (text in `#F7F4EE`) while the inactive side fills with `#E6E1D6` (text in `#6B705C`).

### Potentiometer / Rotary Knobs
- Machined circular dial with cream `#F7F4EE` cap, 1.5px `#17150F` border, and a solid ink position pointer line extending to the rim. Surrounding collar features concentric tick marks in `#6B705C` with critical range highlighted in `#FF5A1F`.

### Linear Sliders
- Notched mechanical well with `#E6E1D6` background, inset border `1.5px solid #17150F`.
- Slider head: Solid rectangular block (`#F7F4EE` or `#FF5A1F` for active param), 1.5px border, horizontal grip incisions, with hard `2px 2px 0px #17150F` shadow.

### Number Steppers
- Unit display framed inside an ink-bordered readout bay: `[ - ] [  0124.50 kHz  ] [ + ]`.
- Buttons are hard-square stepped ink buttons; readout uses bold JetBrains Mono tabular digits.

### Checkboxes & Radios
- **Checkboxes**: Hard-edged square (18x18px), 1.5px `#17150F` outline, `#F7F4EE` background. Checked state is marked with a thick, solid `#17150F` fill and an interior `#FF5A1F` indicator core.
- **Radio Buttons**: Hard-edged diamonds or squares with solid stamped center markers. No rounded circles for binary parameters.

### Telemetry & Readout Cards
- Enclosed with 1.5px solid ink borders and a top-fixed title strip: uppercase `label-caps` in JetBrains Mono against a contrasting background ribbon. Key metrics feature large tabular figures with physical unit flags (e.g., `dB`, `Hz`, `VDC`, `mA`) displayed in `#6B705C`.