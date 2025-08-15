import os
from elasticsearch import Elasticsearch

# The search functionality relies on an external Elasticsearch service. In
# environments where this service isn't available (for example during tests or
# local development) importing this module would raise a connection error. To
# keep the rest of the application functional we attempt to create the client
# and fall back to ``None`` if the service can't be reached. The public
# functions handle the ``None`` case gracefully by becoming no-ops.
def _get_client():
    url = os.environ.get("ELASTIC_URL", "http://localhost:9200")
    try:
        client = Elasticsearch(url)
        # Make a lightweight request to ensure the server is reachable. If this
        # fails the exception will be caught and ``None`` returned.
        client.info()
        return client
    except Exception:
        return None


es = _get_client()
INDEX_NAME = "documents"


def create_index() -> None:
    """Create the index if it doesn't already exist.

    When ``es`` is ``None`` (i.e. the service couldn't be reached) the function
    simply returns without performing any action.
    """

    if es is None:
        return

    mapping = {
        "mappings": {
            "properties": {
                "title": {"type": "text"},
                "code": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "department": {"type": "keyword"},
                "process": {"type": "keyword"},
                "content": {"type": "text"},
            }
        }
    }
    try:
        if not es.indices.exists(index=INDEX_NAME):
            es.indices.create(index=INDEX_NAME, body=mapping)
    except Exception:
        # If the server becomes unavailable between the exists check and the
        # create call, ignore the error and continue without search support.
        pass


def index_document(doc, content: str = "") -> None:
    if es is None:
        return

    body = {
        "title": doc.title,
        "code": doc.code,
        "tags": doc.tags,
        "department": doc.department,
        "process": doc.process,
        "content": content,
    }
    try:
        es.index(index=INDEX_NAME, id=doc.id, document=body)
    except Exception:
        # Swallow errors so a failing search backend doesn't break uploads.
        pass


def search_documents(filters: dict):
    """Search for documents matching the given filter dictionary.

    If the search service isn't available an empty list is returned instead of
    raising an exception.
    """

    if es is None:
        return []

    must = []
    for field, value in filters.items():
        if value:
            if field == "title" or field == "content":
                must.append({"match": {field: value}})
            else:
                must.append({"term": {field: value}})
    query = {"query": {"bool": {"must": must}}}
    try:
        resp = es.search(index=INDEX_NAME, body=query)
    except Exception:
        return []

    return [hit["_source"] | {"id": hit["_id"]} for hit in resp["hits"]["hits"]]


create_index()
