# OnlyOffice Integration

The portal uses [OnlyOffice](https://www.onlyoffice.com/) for document editing. The callback URL provided to OnlyOffice is constructed from the `PORTAL_PUBLIC_BASE_URL` environment variable. When this variable is unset, the application falls back to the incoming request's host URL.

## Environment Variables

- `PORTAL_PUBLIC_BASE_URL`: Public base URL used to build OnlyOffice callback URLs. Defaults to the request's host URL when not defined.
