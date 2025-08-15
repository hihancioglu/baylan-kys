import os
from elasticsearch import Elasticsearch

es = Elasticsearch(os.environ.get("ELASTIC_URL", "http://localhost:9200"))
INDEX_NAME = "documents"


def create_index() -> None:
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
    if not es.indices.exists(index=INDEX_NAME):
        es.indices.create(index=INDEX_NAME, body=mapping)


def index_document(doc, content: str = "") -> None:
    body = {
        "title": doc.title,
        "code": doc.code,
        "tags": doc.tags,
        "department": doc.department,
        "process": doc.process,
        "content": content,
    }
    es.index(index=INDEX_NAME, id=doc.id, document=body)


def search_documents(filters: dict):
    must = []
    for field, value in filters.items():
        if value:
            if field == "title" or field == "content":
                must.append({"match": {field: value}})
            else:
                must.append({"term": {field: value}})
    query = {"query": {"bool": {"must": must}}}
    resp = es.search(index=INDEX_NAME, body=query)
    return [hit["_source"] | {"id": hit["_id"]} for hit in resp["hits"]["hits"]]


create_index()
