from .models import Evidence
WEIGHTS={"info":0,"low":5,"medium":14,"high":28,"critical":45}
def assess(evidence:list[Evidence]):
    # Additive, capped evidence aggregation; no positive signal discounts danger.
    score=min(100, round(sum(WEIGHTS[x.severity]*x.confidence for x in evidence)))
    level="critical" if score>=70 else "high" if score>=40 else "medium" if score>=15 else "low"
    actionable=[x for x in evidence if x.severity in {"high","critical","medium"}]
    if level in {"high","critical"}: rec="Do not open this link until you independently verify the destination."
    elif level=="medium": rec="Verify the destination through a trusted channel before signing in or sharing information."
    else: rec="No high-confidence dangerous indicator was found. Treat unknown links with normal caution."
    summary=(actionable[0].explanation if actionable else "No high-confidence dangerous indicator was found during this limited inspection.")
    return score,level,rec,summary
