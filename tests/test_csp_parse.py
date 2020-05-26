from csp_tool.csp_parser import parse_csp, bulk_parse_csp


def test_empty_entry_returns_none():
    empty_entry = ''

    csp = parse_csp(empty_entry)

    assert None is csp


def test_default_returns_object_with_key():
    entry = 'default-src'

    csp = parse_csp(entry)

    assert 'default-src' in csp.keys()


def test_default_with_keywords_stores_keywords_on_scope():
    entry = "default-src 'self' localhost:9707 localhost:9032 localhost:9250 www.google-analytics.com"
    expected_scope = 'default-src'
    expected_keyword_count = 1
    expected_domain_count = 4

    csp = parse_csp(entry)

    assert expected_scope in csp.keys()
    assert expected_keyword_count == len(csp[expected_scope]['keywords'])
    assert expected_domain_count == len(csp[expected_scope]['domains'])


def test_space_based_parsing():
    # csps are not always reliable if you don't use semicolons but they might still work
    # what if we parse more cleverly by spaces and directive and keyword evaluation?
    # would that hide potential run time issues?
    pass


def test_multiple_scopes_appear_as_correct_keys():
    entry = "frame-ancestors 'self' *.optimizely.com; default-src 'self' 'unsafe-inline' 'unsafe-eval' stats.g.doubleclick.net *.analytics-egain.com www.google-analytics.com *.optimizely.com optimizely.s3.amazonaws.com data:"
    expected_scopes = ['default-src', 'frame-ancestors']

    csp = parse_csp(entry)

    for scope in expected_scopes:
        assert scope in csp.keys()


def test_multiple_keywords_stored_in_expected_scopes():
    entry = "frame-ancestors 'self' *.optimizely.com; default-src 'self' 'unsafe-inline' 'unsafe-eval' stats.g.doubleclick.net *.analytics-egain.com www.google-analytics.com *.optimizely.com optimizely.s3.amazonaws.com data:"
    scope_name = 'default-src'

    csp = parse_csp(entry)

    assert scope_name in csp.keys()
    assert csp[scope_name] is not None

    scope = csp[scope_name]
    assert 'data' in scope.keys()
    assert 3 == len(scope['keywords'])
    assert 5 == len(scope['domains'])


def test_multiple_entries_return_ist_of_objects():
    entries = [
        "default-src 'self' localhost:9707 localhost:9032 localhost:9250 www.google-analytics.com",
        "frame-ancestors 'self' *.optimizely.com; default-src 'self' 'unsafe-inline' 'unsafe-eval' stats.g.doubleclick.net *.analytics-egain.com www.google-analytics.com *.optimizely.com optimizely.s3.amazonaws.com data:"
    ]

    csp_list = bulk_parse_csp(entries)

    assert 2 == len(csp_list)
    assert 1 == len(csp_list[0].keys())
