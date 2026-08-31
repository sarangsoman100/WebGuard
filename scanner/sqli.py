import requests


SQL_ERROR_PATTERNS = [
    "sql syntax",
    "sqlite error",
    "sqlite3",
    "database error",
    "unrecognized token",
    "syntax error",
    "near \"",
    "mysql",
    "postgresql",
    "postgres",
    "ora-",
    "odbc",
    "databaseexception",
]


def _contains_sql_error(text):
    body = (text or "").lower()

    return next(
        (
            pattern
            for pattern in SQL_ERROR_PATTERNS
            if pattern in body
        ),
        None,
    )


def _request(url, parameter, value):
    try:
        return requests.get(
            url,
            params={parameter: value},
            timeout=5,
            allow_redirects=True,
        )
    except requests.RequestException:
        return None


def _is_numeric_parameter(parameter):
    numeric_names = {
        "id",
        "user_id",
        "userid",
        "product_id",
        "productid",
        "item_id",
        "itemid",
        "page",
        "limit",
        "offset",
    }

    return parameter.lower() in numeric_names


def check_sql_injection(url, parameter, mode="standard"):
    """
    Non-destructive SQL injection detection.

    Standard:
        Uses a normal baseline and quote-based error comparison.

    Active:
        Adds controlled boolean response comparisons for parameters
        that appear numeric.

    Returns:
        Finding dictionary or None.
    """

    # ---------------------------------------------------------
    # 1. Choose a reasonable baseline
    # ---------------------------------------------------------

    if _is_numeric_parameter(parameter):
        baseline_value = "1"
    else:
        baseline_value = "WebGuardBaseline"

    baseline = _request(
        url,
        parameter,
        baseline_value,
    )

    if baseline is None:
        return None

    baseline_error = _contains_sql_error(
        baseline.text
    )

    # ---------------------------------------------------------
    # 2. Quote probes
    # ---------------------------------------------------------

    quote_probes = [
        "'",
        '"',
    ]

    for probe in quote_probes:

        response = _request(
            url,
            parameter,
            probe,
        )

        if response is None:
            continue

        error_pattern = _contains_sql_error(
            response.text
        )

        # Strong case:
        #
        # normal baseline works
        # quote causes DB error
        #
        if error_pattern and not baseline_error:

            return {
                "type": "SQL Injection",
                "category": "Vulnerability",
                "name": f"Potential SQL Injection: {parameter}",
                "severity": "High",
                "confidence": "High",
                "description": (
                    f"The parameter '{parameter}' caused a "
                    "database-related error when supplied with "
                    "a SQL syntax probe."
                ),
                "recommendation": (
                    "Use parameterized queries/prepared statements "
                    "and keep database errors out of user-facing "
                    "responses."
                ),
                "parameter": parameter,
                "detection": "Error-based",
                "evidence": (
                    f"Baseline request returned normally, while "
                    f"the probe '{probe}' triggered the SQL error "
                    f"indicator '{error_pattern}'."
                ),
                "url": url,
            }

        # -----------------------------------------------------
        # 3. If both baseline and probe error, compare status
        # -----------------------------------------------------

        if error_pattern and baseline_error:

            if (
                baseline.status_code < 500
                and response.status_code >= 500
            ):
                return {
                    "type": "SQL Injection",
                    "category": "Vulnerability",
                    "name": f"Potential SQL Injection: {parameter}",
                    "severity": "High",
                    "confidence": "Medium",
                    "description": (
                        f"The parameter '{parameter}' produced a "
                        "database error after a SQL syntax probe."
                    ),
                    "recommendation": (
                        "Use parameterized queries/prepared statements "
                        "and validate user-controlled input."
                    ),
                    "parameter": parameter,
                    "detection": "Error-based",
                    "evidence": (
                        f"SQL error indicator '{error_pattern}' "
                        "was detected in the probe response."
                    ),
                    "url": url,
                }

    # ---------------------------------------------------------
    # 4. Active boolean comparison
    # ---------------------------------------------------------

    if mode == "active" and _is_numeric_parameter(parameter):

        true_response = _request(
            url,
            parameter,
            "1 AND 1=1",
        )

        false_response = _request(
            url,
            parameter,
            "1 AND 1=2",
        )

        if (
            true_response is not None
            and false_response is not None
        ):

            true_error = _contains_sql_error(
                true_response.text
            )

            false_error = _contains_sql_error(
                false_response.text
            )

            if not true_error and not false_error:

                true_length = len(
                    true_response.text
                )

                false_length = len(
                    false_response.text
                )

                maximum = max(
                    true_length,
                    false_length,
                )

                if maximum > 0:

                    difference = (
                        abs(
                            true_length - false_length
                        )
                        / maximum
                    )

                    if difference >= 0.25:

                        return {
                            "type": "SQL Injection",
                            "category": "Vulnerability",
                            "name": (
                                f"Potential Boolean SQL Injection: "
                                f"{parameter}"
                            ),
                            "severity": "High",
                            "confidence": "Medium",
                            "description": (
                                f"The parameter '{parameter}' produced "
                                "materially different responses for "
                                "controlled boolean comparison inputs."
                            ),
                            "recommendation": (
                                "Use parameterized queries/prepared "
                                "statements and validate expected input "
                                "types server-side."
                            ),
                            "parameter": parameter,
                            "detection": (
                                "Boolean response comparison"
                            ),
                            "evidence": (
                                f"Response-size difference was "
                                f"{difference:.0%} between controlled "
                                "true and false probes."
                            ),
                            "url": url,
                        }

    return None