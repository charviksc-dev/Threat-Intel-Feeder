import logging
from typing import Any

from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)


class ElasticIndexer:
    def __init__(self, host: str, index: str):
        self.client = Elasticsearch(hosts=[str(host)])
        self.index = index

    def upsert(self, doc_id: str, document: dict[str, Any]) -> None:
        body = {"doc": document, "doc_as_upsert": True}
        self.client.update(index=self.index, id=doc_id, body=body)
        logger.debug("Updated indicator %s into Elasticsearch", doc_id)

    def bulk_upsert(self, documents: list[dict[str, Any]]) -> None:
        actions = []
        for document in documents:
            doc_id = f"{document.get('source')}::{document.get('indicator')}"
            actions.append({"update": {"_index": self.index, "_id": doc_id}})
            actions.append({"doc": document, "doc_as_upsert": True})
        if actions:
            from elasticsearch import helpers

            helpers.bulk(self.client, actions)
            logger.info("Bulk indexed %d indicators", len(documents))
