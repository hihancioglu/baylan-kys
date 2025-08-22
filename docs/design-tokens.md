# Design Tokens

Design tokens centralize style values for colors, typography, spacing, and more. All tokens are defined in `portal/static/css/_tokens.scss` and exposed as CSS variables for JavaScript.

## Usage

### SCSS
```scss
@use '../css/tokens' as *;

.button {
  background-color: $color-primary;
  padding: $spacing-sm;
  border-radius: $radius-md;
}
```

### JavaScript
```javascript
import { getToken } from './tokens.js';

const primary = getToken('color-primary');
```

## Tokens

### Colors
- `$color-primary` / `--color-primary`
- `$color-primary-dark` / `--color-primary-dark`
- `$color-text` / `--color-text`
- `$color-background` / `--color-background`

### Typography
- `$font-size-xxs` / `--font-size-xxs`
- `$font-size-xs` / `--font-size-xs`
- `$font-size-sm` / `--font-size-sm`
- `$font-size-md` / `--font-size-md`
- `$font-size-lg` / `--font-size-lg`
- `$font-size-xl` / `--font-size-xl`

### Border Radius
- `$radius-sm` / `--radius-sm`
- `$radius-md` / `--radius-md`
- `$radius-lg` / `--radius-lg`

### Shadows
- `$shadow-sm` / `--shadow-sm`
- `$shadow-md` / `--shadow-md`
- `$shadow-lg` / `--shadow-lg`

### Spacing
- `$spacing-xs` / `--spacing-xs`
- `$spacing-sm` / `--spacing-sm`
- `$spacing-md` / `--spacing-md`
- `$spacing-lg` / `--spacing-lg`
- `$spacing-xl` / `--spacing-xl`

### Z-Index
- `$z-base` / `--z-base`
- `$z-overlay` / `--z-overlay`
- `$z-dropdown` / `--z-dropdown`
- `$z-sticky` / `--z-sticky`
- `$z-modal` / `--z-modal`
- `$z-popover` / `--z-popover`
- `$z-tooltip` / `--z-tooltip`

### Breakpoints
- `$breakpoint-sm` / `--breakpoint-sm`
- `$breakpoint-md` / `--breakpoint-md`
- `$breakpoint-lg` / `--breakpoint-lg`
