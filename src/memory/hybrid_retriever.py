"""Hybrid retrieval layer — Qdrant vector search + Neo4j knowledge graph.

Provides a unified ``HybridRetriever`` that:
  1. Embeds queries and searches Qdrant for similar threat intel documents
  2. Queries Neo4j for entity-relationship context (Asset → Vulnerability → ThreatActor)
  3. Merges and ranks results for downstream agent consumption
"""

from __future__ import annotations

import logging
from typing import Any

from src.config import get_settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Qdrant Interface
# ═══════════════════════════════════════════════════════════════


class VectorStore:
    """Thin wrapper around the Qdrant client for threat intel embeddings."""

    def __init__(self) -> None:
        settings = get_settings()
        self._host = settings.qdrant_host
        self._port = settings.qdrant_port
        self._collection = settings.qdrant_collection
        self._client: Any | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            from qdrant_client import QdrantClient

            self._client = QdrantClient(host=self._host, port=self._port, check_compatibility=False)
            logger.info("Qdrant client connected → %s:%s", self._host, self._port)
        return self._client

    def ensure_collection(self, vector_size: int = 1536) -> None:
        """Create the collection if it doesn't exist."""
        from qdrant_client.models import Distance, VectorParams

        client = self._get_client()
        collections = [c.name for c in client.get_collections().collections]
        if self._collection not in collections:
            client.create_collection(
                collection_name=self._collection,
                vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
            )
            logger.info("Created Qdrant collection: %s", self._collection)

    def upsert(self, documents: list[dict[str, Any]]) -> int:
        """Upsert documents with pre-computed embeddings.

        Each document dict must have:
          - ``id``: unique string/int identifier
          - ``vector``: list[float] embedding
          - ``payload``: dict of metadata
        """
        from qdrant_client.models import PointStruct

        client = self._get_client()
        points = [
            PointStruct(
                id=doc["id"] if isinstance(doc["id"], int) else hash(doc["id"]) % (2**63),
                vector=doc["vector"],
                payload=doc.get("payload", {}),
            )
            for doc in documents
        ]
        client.upsert(collection_name=self._collection, points=points)
        return len(points)

    def search(
        self,
        query_vector: list[float],
        top_k: int = 5,
        score_threshold: float = 0.5,
    ) -> list[dict[str, Any]]:
        """Search for similar documents by vector."""
        client = self._get_client()
        results = client.query_points(
            collection_name=self._collection,
            query=query_vector,
            limit=top_k,
            score_threshold=score_threshold,
        )
        return [
            {
                "id": str(hit.id),
                "score": hit.score,
                "payload": hit.payload,
            }
            for hit in results.points
        ]


# ═══════════════════════════════════════════════════════════════
#  Neo4j Knowledge Graph Interface
# ═══════════════════════════════════════════════════════════════


class KnowledgeGraph:
    """Thin wrapper around the Neo4j Python driver for threat relationship queries."""

    def __init__(self) -> None:
        settings = get_settings()
        self._uri = settings.neo4j_uri
        self._user = settings.neo4j_user
        self._password = settings.neo4j_password
        self._driver: Any | None = None

    def _get_driver(self) -> Any:
        if self._driver is None:
            from neo4j import GraphDatabase

            self._driver = GraphDatabase.driver(
                self._uri,
                auth=(self._user, self._password),
            )
            logger.info("Neo4j driver connected → %s", self._uri)
        return self._driver

    def close(self) -> None:
        """Close the driver connection."""
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def seed_sample_graph(self) -> None:
        """Populate the graph with sample threat intel relationships.

        Creates nodes for Assets, Vulnerabilities, ThreatActors, and Malware
        with relationships between them.
        """
        driver = self._get_driver()
        cypher = """
        // ── Assets ──
        MERGE (ws:Asset {name: 'web-server-01', ip: '192.168.1.50', type: 'server', criticality: 'high'})
        MERGE (db:Asset {name: 'db-primary', ip: '10.0.1.10', type: 'database', criticality: 'critical'})
        MERGE (fw:Asset {name: 'fw-edge-01', ip: '192.168.1.1', type: 'firewall', criticality: 'critical'})
        MERGE (ws2:Asset {name: 'app-server-02', ip: '192.168.1.51', type: 'server', criticality: 'medium'})

        // ── Vulnerabilities ──
        MERGE (v1:Vulnerability {cve_id: 'CVE-2024-3094', cvss: 10.0, name: 'XZ Utils Backdoor'})
        MERGE (v2:Vulnerability {cve_id: 'CVE-2024-21762', cvss: 9.8, name: 'FortiOS SSL VPN RCE'})
        MERGE (v3:Vulnerability {cve_id: 'CVE-2023-44228', cvss: 9.0, name: 'Log4Shell Variant'})

        // ── Threat Actors ──
        MERGE (ta1:ThreatActor {name: 'APT29', aliases: 'Cozy Bear, Midnight Blizzard', origin: 'Russia'})
        MERGE (ta2:ThreatActor {name: 'FIN7', aliases: 'Carbanak Group', origin: 'Russia'})
        MERGE (ta3:ThreatActor {name: 'Lazarus', aliases: 'Hidden Cobra', origin: 'North Korea'})

        // ── Malware ──
        MERGE (m1:Malware {name: 'Cobalt Strike', type: 'C2 Framework'})
        MERGE (m2:Malware {name: 'Emotet', type: 'Loader/Dropper'})

        // ── Relationships ──
        MERGE (ws)-[:HAS_VULNERABILITY]->(v1)
        MERGE (ws)-[:HAS_VULNERABILITY]->(v3)
        MERGE (fw)-[:HAS_VULNERABILITY]->(v2)
        MERGE (ws2)-[:HAS_VULNERABILITY]->(v3)

        MERGE (ta1)-[:EXPLOITS]->(v1)
        MERGE (ta1)-[:EXPLOITS]->(v2)
        MERGE (ta2)-[:EXPLOITS]->(v2)
        MERGE (ta3)-[:EXPLOITS]->(v3)

        MERGE (ta1)-[:USES_MALWARE]->(m1)
        MERGE (ta2)-[:USES_MALWARE]->(m2)

        MERGE (ta1)-[:TARGETS]->(ws)
        MERGE (ta2)-[:TARGETS]->(fw)
        MERGE (ta3)-[:TARGETS]->(ws2)
        """
        with driver.session() as session:
            session.run(cypher)
        logger.info("Neo4j sample threat graph seeded")

    def query_by_cve(self, cve_id: str) -> list[dict[str, Any]]:
        """Find assets, threat actors, and malware related to a CVE."""
        driver = self._get_driver()
        cypher = """
        MATCH (v:Vulnerability {cve_id: $cve_id})
        OPTIONAL MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v)
        OPTIONAL MATCH (ta:ThreatActor)-[:EXPLOITS]->(v)
        OPTIONAL MATCH (ta)-[:USES_MALWARE]->(m:Malware)
        RETURN v, collect(DISTINCT a) AS assets,
               collect(DISTINCT ta) AS threat_actors,
               collect(DISTINCT m) AS malware
        """
        with driver.session() as session:
            result = session.run(cypher, cve_id=cve_id)
            records = []
            for record in result:
                vuln_node = record["v"]
                records.append(
                    {
                        "vulnerability": dict(vuln_node) if vuln_node else {},
                        "affected_assets": [dict(a) for a in record["assets"] if a],
                        "threat_actors": [dict(ta) for ta in record["threat_actors"] if ta],
                        "malware": [dict(m) for m in record["malware"] if m],
                    }
                )
            return records

    def query_by_ip_or_asset(self, identifier: str) -> list[dict[str, Any]]:
        """Find vulnerabilities and threat actors related to an asset."""
        driver = self._get_driver()
        cypher = """
        MATCH (a:Asset)
        WHERE a.name CONTAINS $identifier OR a.ip = $identifier
        OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        OPTIONAL MATCH (ta:ThreatActor)-[:TARGETS]->(a)
        RETURN a, collect(DISTINCT v) AS vulnerabilities,
               collect(DISTINCT ta) AS threat_actors
        """
        with driver.session() as session:
            result = session.run(cypher, identifier=identifier)
            records = []
            for record in result:
                asset_node = record["a"]
                records.append(
                    {
                        "asset": dict(asset_node) if asset_node else {},
                        "vulnerabilities": [dict(v) for v in record["vulnerabilities"] if v],
                        "threat_actors": [dict(ta) for ta in record["threat_actors"] if ta],
                    }
                )
            return records

    def query_threat_paths(self, asset_name: str, max_depth: int = 4) -> list[dict[str, Any]]:
        """Discover attack paths from threat actors to a target asset."""
        driver = self._get_driver()
        cypher = """
        MATCH path = (ta:ThreatActor)-[*1..$max_depth]->(a:Asset {name: $asset_name})
        RETURN [n IN nodes(path) | {labels: labels(n), props: properties(n)}] AS nodes,
               [r IN relationships(path) | type(r)] AS relationships
        LIMIT 10
        """
        with driver.session() as session:
            result = session.run(cypher, asset_name=asset_name, max_depth=max_depth)
            return [
                {
                    "nodes": record["nodes"],
                    "relationships": record["relationships"],
                }
                for record in result
            ]


# ═══════════════════════════════════════════════════════════════
#  Hybrid Retriever (Vector + Graph)
# ═══════════════════════════════════════════════════════════════


class HybridRetriever:
    """Combines Qdrant vector similarity with Neo4j graph traversal.

    For a given query, the retriever:
      1. Embeds the query and searches Qdrant for similar historical incidents
      2. Extracts entity identifiers (CVEs, IPs, hostnames) and queries the
         knowledge graph for relational context
      3. Returns a merged result set
    """

    def __init__(self) -> None:
        self.vector_store = VectorStore()
        self.knowledge_graph = KnowledgeGraph()

    async def retrieve(
        self,
        query: str,
        query_vector: list[float] | None = None,
        entities: dict[str, list[str]] | None = None,
        top_k: int = 5,
    ) -> dict[str, Any]:
        """Run hybrid retrieval.

        Parameters
        ----------
        query:
            Natural language query or alert text.
        query_vector:
            Pre-computed embedding vector.  If ``None``, vector search is
            skipped.
        entities:
            Dict of entity type → list of values to query the graph.
            E.g. ``{"cve": ["CVE-2024-3094"], "asset": ["web-server-01"]}``
        top_k:
            Max vector search results.

        Returns
        -------
        dict with ``vector_results`` and ``graph_results`` keys.
        """
        result: dict[str, Any] = {
            "query": query,
            "vector_results": [],
            "graph_results": [],
        }

        # ── Vector search ──────────────────────────────────────
        if query_vector is not None:
            try:
                result["vector_results"] = self.vector_store.search(
                    query_vector=query_vector,
                    top_k=top_k,
                )
            except Exception:
                logger.warning("Vector search failed", exc_info=True)

        # ── Graph queries ──────────────────────────────────────
        entities = entities or {}
        graph_data: list[dict[str, Any]] = []

        for cve_id in entities.get("cve", []):
            try:
                records = self.knowledge_graph.query_by_cve(cve_id)
                graph_data.extend(records)
            except Exception:
                logger.warning("Graph query failed for CVE %s", cve_id, exc_info=True)

        for asset in entities.get("asset", []):
            try:
                records = self.knowledge_graph.query_by_ip_or_asset(asset)
                graph_data.extend(records)
            except Exception:
                logger.warning("Graph query failed for asset %s", asset, exc_info=True)

        result["graph_results"] = graph_data
        return result

    def close(self) -> None:
        """Release database connections."""
        self.knowledge_graph.close()
