"""Classical Text-Classification Baseline: TF-IDF + Logistic Regression.

This module provides a classical machine learning baseline for vulnerability detection.
The source code of each function is represented using TF-IDF n-gram features and classified
using Logistic Regression.

This serves as a deliberately simple text-classification baseline that learns from
vulnerable and non-vulnerable training functions without access to repository-level context
or knowledge graphs during inference.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence, Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.agents.schemas import Prediction
from vuln_commit_kg.evaluation.binary import binary_metrics

logger = logging.getLogger(__name__)


class TfidfLogisticRegressionBaseline:
    """TF-IDF + Logistic Regression baseline classifier for vulnerability detection.
    """

    def __init__(
        self,
        max_features: int = 5000,
        ngram_range: tuple[int, int] = (1, 2),
        C: float = 1.0,
        max_iter: int = 1000,
        random_state: int = 42,
        class_weight: str | dict | None = "balanced",
    ) -> None:
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.C = C
        self.max_iter = max_iter
        self.random_state = random_state
        self.class_weight = class_weight

        # Custom token pattern tailored for C/C++ source code: tokens include identifiers,
        # operators, and delimiters
        self.vectorizer = TfidfVectorizer(
            max_features=self.max_features,
            ngram_range=self.ngram_range,
            token_pattern=r"(?u)\b[A-Za-z_]\w*\b|[^\w\s]",
            lowercase=False,
        )
        self.classifier = LogisticRegression(
            C=self.C,
            max_iter=self.max_iter,
            random_state=self.random_state,
            class_weight=self.class_weight,
        )
        self._is_fitted = False

    def fit(self, samples: Sequence[SecVulEvalSample]) -> "TfidfLogisticRegressionBaseline":
        """Train the TF-IDF vectorizer and Logistic Regression model on function bodies."""
        if not samples:
            raise ValueError("Cannot fit baseline on an empty sample list.")

        texts = [s.func_body or "" for s in samples]
        labels = [int(bool(s.is_vulnerable)) for s in samples]

        unique_labels = set(labels)
        if len(unique_labels) < 2:
            raise ValueError(
                f"Training data must contain at least two classes (vulnerable and non-vulnerable). "
                f"Found unique classes: {unique_labels}"
            )

        X = self.vectorizer.fit_transform(texts)
        self.classifier.fit(X, labels)
        self._is_fitted = True
        return self

    def predict_sample(self, sample: SecVulEvalSample) -> Prediction:
        """Predict vulnerability for a single function sample and return a Prediction object."""
        if not self._is_fitted:
            raise RuntimeError("The baseline model must be fitted before running predictions.")

        text = sample.func_body or ""
        X = self.vectorizer.transform([text])
        pred_label = bool(self.classifier.predict(X)[0])
        probabilities = self.classifier.predict_proba(X)[0]
        confidence = float(probabilities[1] if pred_label else probabilities[0])

        return Prediction(
            sample_id=sample.sample_id,
            dataset_commit_id=sample.commit_id,
            resolved_commit_id=sample.commit_id,
            is_vulnerable=pred_label,
            confidence=confidence,
            decision_status="vulnerable" if pred_label else "non_vulnerable",
            reasoning_summary=(
                f"Classical baseline decision via TF-IDF + Logistic Regression. "
                f"Probability vulnerable: {probabilities[1]:.4f}, non-vulnerable: {probabilities[0]:.4f}."
            ),
            model_backend="tfidf_logistic_regression",
        )

    def predict(self, samples: Sequence[SecVulEvalSample]) -> list[Prediction]:
        """Generate Prediction objects for a batch of samples."""
        if not self._is_fitted:
            raise RuntimeError("The baseline model must be fitted before running predictions.")

        texts = [s.func_body or "" for s in samples]
        X = self.vectorizer.transform(texts)
        preds = self.classifier.predict(X)
        probas = self.classifier.predict_proba(X)

        results: list[Prediction] = []
        for i, s in enumerate(samples):
            pred_label = bool(preds[i])
            conf = float(probas[i][1] if pred_label else probas[i][0])
            results.append(
                Prediction(
                    sample_id=s.sample_id,
                    dataset_commit_id=s.commit_id,
                    resolved_commit_id=s.commit_id,
                    is_vulnerable=pred_label,
                    confidence=conf,
                    decision_status="vulnerable" if pred_label else "non_vulnerable",
                    reasoning_summary=(
                        f"Classical baseline decision via TF-IDF + Logistic Regression. "
                        f"Probability vulnerable: {probas[i][1]:.4f}, non-vulnerable: {probas[i][0]:.4f}."
                    ),
                    model_backend="tfidf_logistic_regression",
                )
            )
        return results

    def evaluate(self, samples: Sequence[SecVulEvalSample]) -> dict[str, Any]:
        """Predict and evaluate directly against ground truth using standard binary metrics."""
        preds = self.predict(samples)
        return binary_metrics(samples, preds)

    def save(self, path: str | Path) -> None:
        """Save the fitted model and vectorizer to disk."""
        if not self._is_fitted:
            raise RuntimeError("Cannot save an unfitted baseline model.")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "vectorizer": self.vectorizer,
                "classifier": self.classifier,
                "max_features": self.max_features,
                "ngram_range": self.ngram_range,
                "C": self.C,
                "max_iter": self.max_iter,
                "random_state": self.random_state,
                "class_weight": self.class_weight,
            },
            path,
        )

    @classmethod
    def load(cls, path: str | Path) -> "TfidfLogisticRegressionBaseline":
        """Load a saved model and vectorizer from disk."""
        data = joblib.load(path)
        instance = cls(
            max_features=data["max_features"],
            ngram_range=data["ngram_range"],
            C=data["C"],
            max_iter=data["max_iter"],
            random_state=data["random_state"],
            class_weight=data.get("class_weight", "balanced"),
        )
        instance.vectorizer = data["vectorizer"]
        instance.classifier = data["classifier"]
        instance._is_fitted = True
        return instance
