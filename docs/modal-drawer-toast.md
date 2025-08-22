# Modal, Drawer & Toast Components

Reusable UI elements available under `portal/static/dist/components`.

## Confirmation Modal

```javascript
import { confirmationModal } from './components';

confirmationModal('Delete this item?', () => {
  // run on confirm
});
```

The modal traps focus while open and closes on **ESC** or overlay click.

## XL Modal

```javascript
import { xlModal } from './components';

const modal = xlModal('Large Modal', '<p>Content here</p>');
// modal.close() to dismiss
```

Use the XL variant for wide content. It shares the same closing and focus behavior as the confirmation modal.

## Right-side Drawer

```javascript
import { openDrawer } from './components';

const drawer = openDrawer('<h2>Details</h2><p>Drawer content</p>');
// drawer.close() to dismiss
```

The drawer slides in from the right, traps focus, and closes on **ESC** or overlay click.

## Toast Notifications

```javascript
import { showToast } from './components';

showToast('Saved successfully');
```

Toasts stack in the top-right corner and each includes a close button. Multiple toasts can appear simultaneously.
