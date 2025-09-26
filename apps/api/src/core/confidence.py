"""
Confidence scoring algorithms for threat intelligence data.
"""

import math
from datetime import datetime
from typing import Any


class ConfidenceAlgorithms:
    """
    Advanced confidence scoring algorithms for threat intelligence entities.

    Implements industry-standard confidence scoring methodologies with
    adjustable weights and decay functions for temporal relevance.
    """

    @staticmethod
    def calculate_source_confidence(
        source_reputation: float,
        source_track_record: int,
        source_verification_level: str,
    ) -> float:
        """
        Calculate confidence based on intelligence source characteristics.

        Args:
            source_reputation: Source reputation score (0.0-1.0)
            source_track_record: Number of validated reports from source
            source_verification_level: verified|unverified|unknown

        Returns:
            float: Source confidence score (0.0-1.0)
        """
        # Base reputation weight (60%)
        reputation_score = source_reputation * 0.6

        # Track record weight (30%) with logarithmic scaling
        track_record_score = (
            min(1.0, math.log10(max(1, source_track_record)) / 3.0) * 0.3
        )

        # Verification level weight (10%)
        verification_scores = {"verified": 1.0, "unverified": 0.5, "unknown": 0.2}
        verification_score = (
            verification_scores.get(source_verification_level, 0.2) * 0.1
        )

        return min(1.0, reputation_score + track_record_score + verification_score)

    @staticmethod
    def calculate_temporal_decay(
        observation_date: datetime,
        half_life_days: int = 365,
        current_date: datetime | None = None,
    ) -> float:
        """
        Calculate temporal decay factor for intelligence data.

        Args:
            observation_date: When intelligence was observed
            half_life_days: Days for confidence to decay to 50%
            current_date: Current date (defaults to now)

        Returns:
            float: Decay factor (0.0-1.0)
        """
        if current_date is None:
            current_date = datetime.utcnow()

        # Calculate age in days
        age_days = (current_date - observation_date).days

        if age_days <= 0:
            return 1.0

        # Exponential decay: confidence = e^(-ln(2) * age / half_life)
        decay_constant = math.log(2) / half_life_days
        decay_factor = math.exp(-decay_constant * age_days)

        return max(0.0, min(1.0, decay_factor))

    @staticmethod
    def calculate_attribution_confidence(
        technical_indicators: int,
        behavioral_patterns: int,
        infrastructure_overlap: int,
        timeline_correlation: float,
        witness_reports: int = 0,
    ) -> float:
        """
        Calculate threat actor attribution confidence.

        Args:
            technical_indicators: Count of technical IOCs linking to actor
            behavioral_patterns: Count of behavioral TTPs matching actor
            infrastructure_overlap: Count of shared infrastructure elements
            timeline_correlation: Timeline correlation score (0.0-1.0)
            witness_reports: Count of human intelligence reports

        Returns:
            float: Attribution confidence score (0.0-1.0)
        """
        factors = []

        # Technical indicators (30% weight)
        tech_score = min(
            1.0, technical_indicators / 10.0
        )  # Normalized to 10+ indicators = 1.0
        factors.append(tech_score * 0.3)

        # Behavioral patterns (25% weight)
        behavior_score = min(
            1.0, behavioral_patterns / 8.0
        )  # Normalized to 8+ patterns = 1.0
        factors.append(behavior_score * 0.25)

        # Infrastructure overlap (20% weight)
        infra_score = min(
            1.0, infrastructure_overlap / 5.0
        )  # Normalized to 5+ overlaps = 1.0
        factors.append(infra_score * 0.2)

        # Timeline correlation (15% weight)
        factors.append(timeline_correlation * 0.15)

        # Human intelligence (10% weight)
        humint_score = min(1.0, witness_reports / 3.0)  # Normalized to 3+ reports = 1.0
        factors.append(humint_score * 0.1)

        return min(1.0, sum(factors))

    @staticmethod
    def calculate_detection_confidence(
        true_positive_rate: float,
        false_positive_rate: float,
        deployment_coverage: float,
        validation_tests: int,
        production_detections: int = 0,
    ) -> float:
        """
        Calculate detection rule confidence based on performance metrics.

        Args:
            true_positive_rate: TPR from testing (0.0-1.0)
            false_positive_rate: FPR from testing (0.0-1.0)
            deployment_coverage: Environment coverage percentage (0.0-1.0)
            validation_tests: Number of validation test cases
            production_detections: Number of production detections

        Returns:
            float: Detection confidence score (0.0-1.0)
        """
        factors = []

        # True positive rate (40% weight)
        factors.append(true_positive_rate * 0.4)

        # False positive penalty (20% weight)
        fp_penalty = max(0.0, 1.0 - (false_positive_rate * 2.0))  # Heavy penalty for FP
        factors.append(fp_penalty * 0.2)

        # Deployment coverage (20% weight)
        factors.append(deployment_coverage * 0.2)

        # Validation thoroughness (15% weight)
        validation_score = min(
            1.0, validation_tests / 20.0
        )  # Normalized to 20+ tests = 1.0
        factors.append(validation_score * 0.15)

        # Production validation (5% weight)
        production_score = min(
            1.0, production_detections / 10.0
        )  # Normalized to 10+ detections = 1.0
        factors.append(production_score * 0.05)

        return min(1.0, sum(factors))

    @staticmethod
    def calculate_intelligence_confidence(
        source_confidence: float,
        corroboration_count: int,
        technical_validation: bool,
        analyst_assessment: float,
        temporal_relevance: float,
    ) -> float:
        """
        Calculate overall intelligence confidence score.

        Args:
            source_confidence: Confidence in intelligence source (0.0-1.0)
            corroboration_count: Number of corroborating sources
            technical_validation: Whether technical validation was performed
            analyst_assessment: Analyst confidence rating (0.0-1.0)
            temporal_relevance: Temporal decay factor (0.0-1.0)

        Returns:
            float: Overall intelligence confidence (0.0-1.0)
        """
        factors = []

        # Source confidence (30% weight)
        factors.append(source_confidence * 0.3)

        # Corroboration (25% weight)
        corroboration_score = min(
            1.0, corroboration_count / 3.0
        )  # Normalized to 3+ sources = 1.0
        factors.append(corroboration_score * 0.25)

        # Technical validation (20% weight)
        validation_score = 1.0 if technical_validation else 0.5
        factors.append(validation_score * 0.2)

        # Analyst assessment (15% weight)
        factors.append(analyst_assessment * 0.15)

        # Temporal relevance (10% weight)
        factors.append(temporal_relevance * 0.1)

        return min(1.0, sum(factors))

    @staticmethod
    def calculate_composite_confidence(
        confidence_scores: list[float], weights: list[float] | None = None
    ) -> float:
        """
        Calculate weighted composite confidence from multiple scores.

        Args:
            confidence_scores: List of individual confidence scores
            weights: Optional weights (defaults to equal weighting)

        Returns:
            float: Composite confidence score (0.0-1.0)
        """
        if not confidence_scores:
            return 0.0

        if weights is None:
            weights = [1.0 / len(confidence_scores)] * len(confidence_scores)

        if len(weights) != len(confidence_scores):
            raise ValueError("Weights and scores must have same length")

        # Normalize weights
        total_weight = sum(weights)
        if total_weight == 0:
            return 0.0

        normalized_weights = [w / total_weight for w in weights]

        # Calculate weighted average
        weighted_sum = sum(
            score * weight
            for score, weight in zip(confidence_scores, normalized_weights, strict=False)
        )

        return min(1.0, max(0.0, weighted_sum))

    @staticmethod
    def get_confidence_level_description(confidence_score: float) -> str:
        """
        Get human-readable confidence level description.

        Args:
            confidence_score: Confidence score (0.0-1.0)

        Returns:
            str: Confidence level description
        """
        if confidence_score >= 0.9:
            return "Very High"
        if confidence_score >= 0.7:
            return "High"
        if confidence_score >= 0.5:
            return "Medium"
        if confidence_score >= 0.3:
            return "Low"
        return "Very Low"

    @staticmethod
    def get_confidence_color(confidence_score: float) -> str:
        """
        Get color code for confidence visualization.

        Args:
            confidence_score: Confidence score (0.0-1.0)

        Returns:
            str: Hex color code
        """
        confidence_colors = {
            0.9: "#2E7D32",  # Dark green - Very High
            0.7: "#66BB6A",  # Green - High
            0.5: "#FFA726",  # Orange - Medium
            0.3: "#FF7043",  # Red-orange - Low
            0.0: "#E53935",  # Red - Very Low
        }

        for threshold in sorted(confidence_colors.keys(), reverse=True):
            if confidence_score >= threshold:
                return confidence_colors[threshold]

        return confidence_colors[0.0]


class ConfidenceHistory:
    """
    Track confidence score changes over time for auditing and analysis.
    """

    @staticmethod
    def create_confidence_snapshot(
        entity_id: str,
        entity_type: str,
        confidence_score: float,
        calculation_method: str,
        factors: dict[str, Any],
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        """
        Create a confidence calculation snapshot for audit trail.

        Args:
            entity_id: ID of the entity being scored
            entity_type: Type of entity (threat_actor, detection, etc.)
            confidence_score: Calculated confidence score
            calculation_method: Method used for calculation
            factors: Factors that contributed to the score
            timestamp: When calculation was performed

        Returns:
            Dict: Confidence snapshot for storage
        """
        if timestamp is None:
            timestamp = datetime.utcnow()

        return {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "confidence_score": confidence_score,
            "calculation_method": calculation_method,
            "factors": factors,
            "timestamp": timestamp.isoformat(),
            "confidence_level": ConfidenceAlgorithms.get_confidence_level_description(
                confidence_score
            ),
        }
