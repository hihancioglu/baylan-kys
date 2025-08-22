# State Components

Reusable UI helpers for displaying loading, empty and error states.

## Installation

Import the helpers directly from `state-components.js` located in `portal/static`.

```
import { createSkeleton, createNoData, createErrorCard } from './state-components';
```

## Examples

### Skeleton Placeholder

```
const list = document.getElementById('list');
list.replaceChildren(createSkeleton());
```

### No Data View

```
const container = document.getElementById('results');
container.replaceChildren(createNoData('Nothing to show'));
```

### Error Card with Retry

```
const wrap = document.getElementById('table');
wrap.replaceChildren(
  createErrorCard('Failed to load', () => location.reload())
);
```
