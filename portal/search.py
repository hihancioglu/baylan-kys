import os
import json
from functools import lru_cache

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
                "status": {"type": "keyword"},
                "type": {"type": "keyword"},
                "standard": {"type": "keyword"},
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

    # ``doc.standards`` is a relationship yielding ``DocumentStandard``
    # instances. Collect all associated codes so that a document can be indexed
    # under multiple standards. If no relationship entries exist we fall back to
    # the legacy single ``standard_code`` attribute for backward compatibility.
    standards = [s.standard_code for s in getattr(doc, "standards", [])]
    if not standards:
        legacy = getattr(doc, "standard_code", None)
        if legacy:
            standards = [legacy]

    body = {
        "title": doc.title,
        "code": doc.code,
        "tags": doc.tags,
        "department": doc.department,
        "status": getattr(doc, "status", ""),
        "type": getattr(doc, "type", ""),
        "standard": standards,
        "content": content,
    }
    try:
        es.index(index=INDEX_NAME, id=doc.id, document=body)
    except Exception:
        # Swallow errors so a failing search backend doesn't break uploads.
        pass


@lru_cache(maxsize=128)
def _cached_search(query_json: str):
    """Execute the Elasticsearch query represented by ``query_json``.

    The JSON string is used as the cache key so identical queries can be
    returned quickly without hitting the backend, helping to keep response
    times low.
    """

    return es.search(index=INDEX_NAME, body=json.loads(query_json))


def search_documents(keyword: str, filters: dict, page: int = 1, per_page: int = 10):
    """Search for documents matching the given keyword and filters.

    Returns a tuple of ``(results, facets, total)`` where ``results`` is a list
    of matching documents, ``facets`` contains aggregation counts for the
    ``department``, ``status`` and ``type`` fields and ``total`` is the overall
    number of hits.
    """

    if es is None:
        raise RuntimeError("Search service unavailable")

    must = []
    if keyword:
        must.append({"multi_match": {"query": keyword, "fields": ["title^2", "content"]}})
    for field in ["department", "status", "type", "standard"]:
        value = filters.get(field)
        if value:
            must.append({"term": {field: value}})

    query = {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "size": per_page,
        "from": (page - 1) * per_page,
        "aggs": {
            "department": {"terms": {"field": "department"}},
            "status": {"terms": {"field": "status"}},
            "type": {"terms": {"field": "type"}},
            "standard": {"terms": {"field": "standard"}},
        },
    }

    try:
        resp = _cached_search(json.dumps(query, sort_keys=True))
    except Exception as exc:
        raise RuntimeError("Search query failed") from exc

    results = [hit["_source"] | {"id": hit["_id"]} for hit in resp["hits"]["hits"]]
    aggs = {}
    for facet in ["department", "status", "type", "standard"]:
        buckets = resp.get("aggregations", {}).get(facet, {}).get("buckets", [])
        aggs[facet] = {b["key"]: b["doc_count"] for b in buckets}

    total = resp.get("hits", {}).get("total", {}).get("value", 0)

    return results, aggs, total
