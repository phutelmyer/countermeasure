"""
Detection deduplication logic for the collector pipeline.
"""

import hashlib
from typing import Any, Dict, List, Set

from src.core.logging import get_logger
from src.schemas.detection import DetectionCreate


logger = get_logger(__name__)


class DetectionDeduplicator:
    """Handles deduplication of detection rules based on various strategies."""

    def __init__(self, dedup_strategy: str = "content_hash"):
        """
        Initialize deduplicator.

        Args:
            dedup_strategy: Strategy for deduplication:
                - "content_hash": Hash rule content and metadata
                - "name_author": Match by name and author
                - "sigma_id": Match by SIGMA rule ID
                - "content_semantic": Semantic content analysis
        """
        self.strategy = dedup_strategy
        self.seen_hashes: Set[str] = set()
        self.seen_signatures: Set[str] = set()
        self.duplicate_count = 0

    def deduplicate(self, detections: List[DetectionCreate]) -> List[DetectionCreate]:
        """
        Remove duplicate detections from list.

        Args:
            detections: List of detection objects

        Returns:
            List of unique detections
        """
        unique_detections = []
        self.duplicate_count = 0

        for detection in detections:
            if not self._is_duplicate(detection):
                unique_detections.append(detection)
            else:
                self.duplicate_count += 1

        logger.info(
            f"Deduplication complete: {len(unique_detections)} unique, "
            f"{self.duplicate_count} duplicates removed"
        )

        return unique_detections

    def _is_duplicate(self, detection: DetectionCreate) -> bool:
        """Check if detection is a duplicate based on selected strategy."""
        if self.strategy == "content_hash":
            return self._check_content_hash(detection)
        elif self.strategy == "name_author":
            return self._check_name_author(detection)
        elif self.strategy == "sigma_id":
            return self._check_sigma_id(detection)
        elif self.strategy == "content_semantic":
            return self._check_semantic_content(detection)
        else:
            logger.warning(f"Unknown deduplication strategy: {self.strategy}")
            return False

    def _check_content_hash(self, detection: DetectionCreate) -> bool:
        """Check for duplicates using content hash."""
        # Create hash from rule content and key metadata
        content_parts = [
            detection.name or "",
            detection.description or "",
            detection.rule_content or "",
            detection.author or "",
            str(sorted(detection.platforms or [])),
            str(sorted(detection.data_sources or [])),
        ]

        content_string = "|".join(content_parts)
        content_hash = hashlib.sha256(content_string.encode()).hexdigest()

        if content_hash in self.seen_hashes:
            logger.debug(f"Duplicate detected (content_hash): {detection.name}")
            return True

        self.seen_hashes.add(content_hash)
        return False

    def _check_name_author(self, detection: DetectionCreate) -> bool:
        """Check for duplicates using name and author."""
        signature = f"{detection.name}|{detection.author or 'unknown'}"

        if signature in self.seen_signatures:
            logger.debug(f"Duplicate detected (name_author): {detection.name}")
            return True

        self.seen_signatures.add(signature)
        return False

    def _check_sigma_id(self, detection: DetectionCreate) -> bool:
        """Check for duplicates using SIGMA rule ID."""
        # Extract SIGMA ID from rule content or metadata
        sigma_id = self._extract_sigma_id(detection)

        if not sigma_id:
            # No SIGMA ID found, check by content hash as fallback
            return self._check_content_hash(detection)

        if sigma_id in self.seen_signatures:
            logger.debug(f"Duplicate detected (sigma_id): {sigma_id}")
            return True

        self.seen_signatures.add(sigma_id)
        return False

    def _check_semantic_content(self, detection: DetectionCreate) -> bool:
        """Check for duplicates using semantic content analysis."""
        # Create normalized content signature
        rule_content = detection.rule_content or ""

        # Extract key detection elements for comparison
        signature_elements = []

        # Add normalized rule name
        if detection.name:
            signature_elements.append(detection.name.lower().strip())

        # Add key patterns from rule content (simplified)
        if "selection:" in rule_content:
            # Extract selection criteria patterns
            lines = rule_content.split("\n")
            for line in lines:
                if "selection:" in line or line.strip().startswith("-"):
                    signature_elements.append(line.strip().lower())

        # Add platform and data source info
        if detection.platforms:
            signature_elements.extend([p.lower() for p in detection.platforms])

        if detection.data_sources:
            signature_elements.extend([ds.lower() for ds in detection.data_sources])

        # Create semantic signature
        semantic_sig = "|".join(sorted(signature_elements))
        semantic_hash = hashlib.sha256(semantic_sig.encode()).hexdigest()

        if semantic_hash in self.seen_hashes:
            logger.debug(f"Duplicate detected (semantic): {detection.name}")
            return True

        self.seen_hashes.add(semantic_hash)
        return False

    def _extract_sigma_id(self, detection: DetectionCreate) -> str | None:
        """Extract SIGMA rule ID from detection metadata."""
        try:
            rule_content = detection.rule_content or ""

            # Look for id field in YAML content
            for line in rule_content.split("\n"):
                if line.strip().startswith("id:"):
                    sigma_id = line.split(":", 1)[1].strip()
                    return sigma_id

            # Check if ID is in structured metadata
            if hasattr(detection, 'structured_metadata'):
                metadata = detection.structured_metadata or {}
                if 'id' in metadata:
                    return str(metadata['id'])

        except Exception as e:
            logger.debug(f"Failed to extract SIGMA ID: {e}")

        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        return {
            "strategy": self.strategy,
            "duplicates_removed": self.duplicate_count,
            "unique_signatures_seen": len(self.seen_signatures),
            "unique_hashes_seen": len(self.seen_hashes),
        }

    def reset(self) -> None:
        """Reset deduplicator state."""
        self.seen_hashes.clear()
        self.seen_signatures.clear()
        self.duplicate_count = 0