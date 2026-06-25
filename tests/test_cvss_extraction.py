from agent.cvss_extraction import extract_cvss_vector


def test_extracts_v31_inline():
    text = (
        "The issue is fixed in v1.2.3. The CVSS score is 7.5 "
        "(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) high severity."
    )
    assert (
        extract_cvss_vector(text)
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    )


def test_extracts_v40():
    text = "Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    assert extract_cvss_vector(text) == text.split("Vector: ", 1)[1]


def test_returns_none_when_no_vector():
    assert extract_cvss_vector("A bug was found in ansible. No vector here.") is None


def test_ignores_invalid_candidate_and_keeps_looking():
    # one bogus metric value, then a valid one
    text = (
        "bad: CVSS:3.1/AV:BOGUS/AC:L ; "
        "good: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    )
    assert extract_cvss_vector(text) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


def test_ignores_cvss2():
    # v2 vectors are not surfaced by the regex (require CVSS:3./4. prefix)
    assert extract_cvss_vector("AV:N/AC:L/Au:N/C:N/I:N/A:P") is None


def test_ignores_cvss_3_0():
    # only 3.1 and 4.0 are supported; 3.0 is not surfaced by the regex
    assert extract_cvss_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") is None
