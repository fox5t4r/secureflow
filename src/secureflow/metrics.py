"""Ground truth is loaded only after diagnostic results have been persisted."""


def confusion(truth, predicted):
    if set(truth) != set(predicted):
        raise ValueError("Evaluation case IDs differ")
    counts = {key: 0 for key in ("tp", "fp", "tn", "fn")}
    for key, actual in truth.items():
        counts[
            "tp"
            if actual and predicted[key]
            else "fn"
            if actual
            else "fp"
            if predicted[key]
            else "tn"
        ] += 1
    tp, fp, tn, fn = (counts[k] for k in ("tp", "fp", "tn", "fn"))

    def ratio(a, b):
        return a / b if b else None

    return dict(
        **counts,
        fpr=ratio(fp, fp + tn),
        precision=ratio(tp, tp + fp),
        recall=ratio(tp, tp + fn),
        fdr=ratio(fp, tp + fp),
    )


def evaluate(truth, findings):
    baseline = confusion(truth, {f["id"]: bool(f["sast"]) for f in findings})
    validated = confusion(truth, {f["id"]: f["state"] == "confirmed" for f in findings})
    unknown = [f["id"] for f in findings if f["state"] == "inconclusive"]
    # Conservative view: an untested static alert remains actionable.
    conservative = confusion(
        truth,
        {
            f["id"]: f["state"] == "confirmed" or (f["state"] == "inconclusive" and bool(f["sast"]))
            for f in findings
        },
    )
    delta = (baseline["fpr"] - validated["fpr"]) * 100
    return dict(
        baseline=baseline,
        validated=validated,
        conservative=conservative,
        inconclusive=unknown,
        coverage=(len(findings) - len(unknown)) / len(findings),
        fpr_reduction_pp=delta,
        target_met=delta >= 20 and not unknown,
        unit="case (one endpoint and one vulnerability type)",
        limitation=f"자체 제작 {len(findings)}개 사례의 합성 마이크로벤치마크. 일반 앱 성능이나 통계적 유의성을 입증하지 않음.",
    )
