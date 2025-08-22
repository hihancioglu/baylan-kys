# Static Assets

## Data Table Component

The `data-table.js` file provides a client-side table with sorting, sticky
headers, responsive wrapping, pagination and selectable rows. Mock data with
more than 10,000 records is generated on load to test performance. Styles for
the component are included in the global `app.css` file.

### HTMX Initialization

Include the script in your template and place a container element with the
`data-component="data-table"` attribute where the table should render.

```html
<link rel="stylesheet" href="/static/app.css">
<script type="module" src="/static/data-table-<hash>.js"></script>
<div data-component="data-table"></div>
```

When content is swapped in by HTMX, re-initialize the component on the
`htmx:load` event:

```javascript
import { initDataTable } from '/static/data-table-<hash>.js';
document.body.addEventListener('htmx:load', (evt) => {
  evt.target.querySelectorAll('[data-component="data-table"]').forEach(initDataTable);
});
```
