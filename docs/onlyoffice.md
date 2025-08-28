# OnlyOffice Integration

The portal uses [OnlyOffice](https://www.onlyoffice.com/) for document editing. The callback URL provided to OnlyOffice is constructed from the `PORTAL_PUBLIC_BASE_URL` environment variable. When this variable is unset, the application falls back to the incoming request's host URL.

## Environment Variables

- `PORTAL_PUBLIC_BASE_URL`: Public base URL used to build OnlyOffice callback URLs. Defaults to the request's host URL when not defined.
- `ONLYOFFICE_INTERNAL_URL`: Base URL the portal uses to contact the Document Server.
- `ONLYOFFICE_PUBLIC_URL`: Publicly reachable URL of the Document Server used by the browser.
- `ONLYOFFICE_JWT_SECRET`: Shared secret for signing JWT payloads.
- `ONLYOFFICE_JWT_HEADER`: HTTP header name that carries the JWT. Defaults to `Authorization`.
