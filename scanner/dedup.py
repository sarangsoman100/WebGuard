def deduplicate_findings(findings):
    """
    Deduplicate findings by vulnerability identity while preserving all
    affected endpoints, parameters, evidence and confidence information.
    """

    unique = {}

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue

        key = (
            finding.get("type"),
            finding.get("name"),
            finding.get("severity"),
            finding.get("parameter"),
        )

        endpoint = finding.get("url") or finding.get("endpoint")

        if key not in unique:
            item = {
                "type": finding.get("type", "Unknown"),
                "category": finding.get("category", "Vulnerability"),
                "name": finding.get("name", "Unnamed finding"),
                "severity": finding.get("severity", "Info"),
                "confidence": finding.get("confidence", "Medium"),
                "description": finding.get("description", ""),
                "recommendation": finding.get("recommendation", ""),
                "parameter": finding.get("parameter"),
                "detection": finding.get("detection"),
                "evidence": finding.get("evidence"),
                "affected_endpoints": [],
            }

            if endpoint:
                item["affected_endpoints"].append(endpoint)

            unique[key] = item

        else:
            item = unique[key]

            if endpoint and endpoint not in item["affected_endpoints"]:
                item["affected_endpoints"].append(endpoint)

            # Keep the strongest available evidence.
            if not item.get("evidence") and finding.get("evidence"):
                item["evidence"] = finding["evidence"]

            if not item.get("detection") and finding.get("detection"):
                item["detection"] = finding["detection"]

            if finding.get("confidence") == "High":
                item["confidence"] = "High"

    return list(unique.values())
