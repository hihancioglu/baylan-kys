# Database Migrations

This project uses [Alembic](https://alembic.sqlalchemy.org/) for managing
database schema changes.

## Running migrations

The application now executes pending migrations automatically during startup.
For manual invocation (for example in development), ensure the `DATABASE_URL`
environment variable points to the target database and run:

```bash
alembic upgrade head
```

## Creating a new migration

1. Update the SQLAlchemy models under `portal/models.py`.
2. Generate a migration script:

   ```bash
   alembic revision --autogenerate -m "describe change"
   ```

3. Review the generated file in `alembic/versions/` and adjust as needed.
4. Apply the migration with `alembic upgrade head`.

Migrations replace any implicit `Base.metadata.create_all` calls. Developers
must run the commands above to create or update the database schema.
