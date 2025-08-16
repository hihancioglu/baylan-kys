# Report Export Endpoints

The reporting API supports JSON responses for use in dashboards and optional CSV or PDF exports for offline analysis.

## Request

```
GET /reports/<kind>?start=YYYY-MM-DD&end=YYYY-MM-DD&format=csv|pdf
```

- `start` and `end` are optional ISO dates used to filter the report range.
- `format` defaults to `json`. Specify `csv` or `pdf` to trigger a file download.

## Available Reports

| kind              | description                   |
|-------------------|-------------------------------|
| `training`        | Reading compliance results    |
| `pending-approvals` | Pending approval details     |
| `revisions`       | Document revision history     |

Each export returns a file named `<kind>.<ext>` where `<ext>` matches the requested format.
