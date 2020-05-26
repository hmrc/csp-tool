import pytest
from csp_tool.csp_analyser import get_domains_per_directive, rollup_data_by_header, \
    check_unsafe_inline_used_without_domains, extract_policies_without_domains, check_keyword_used_without_domains


def generate_known_test_data():
    # for reference expected data_headers = ['repo','file','full_csp','has_unsafe_eval','has_unsafe_inline', 'refs_localhost']
    return [
        "repo1, file1, default-src 'self' 'unsafe-inline' www.google-analytics.com data:,'0','1','0'",
        "repo1, file1, default-src 'self' 'unsafe-inline' 'unsafe-eval','1','1','0'",
        "repo1, file1, default-src 'self' 'unsafe-inline' www.google-analytics.com data:,'0','1','0'",
        "repo1, file1, default-src 'self' 'unsafe-inline' data:,'0','1','0'",
        "repo1, file1, default-src 'self' 'unsafe-inline' localhost:9042 data:,'0','1','1'"
    ]


@pytest.mark.parametrize(
    "header,expected_num_rows,biggest_count_row,expected_count",
    [
        ('full_csp', 4, 3, '2'),
        ('has_unsafe_inline', 1, 0, '5'),
        ('has_unsafe_eval', 2, 1, '1'),
        ('refs_localhost', 2, 1, '1'),
    ],
)
def test_rollup_data_by_header(header, expected_num_rows, biggest_count_row, expected_count):
    data = generate_known_test_data()
    data_headers = ['repo', 'file', 'full_csp', 'has_unsafe_eval', 'has_unsafe_inline', 'refs_localhost']
    analysed = rollup_data_by_header(data, header, active_only=False, headers=data_headers)

    assert len(analysed) == expected_num_rows
    assert analysed[biggest_count_row].startswith(expected_count)


def test_get_domains_per_directive_single_directive_returns_correct_domains():
    data = [
        "repo1, file1, default-src 'self' 'unsafe-inline' www.google-analytics.com data:,'0','1','0'",
    ]

    expected_directive = 'default-src'
    expected_domain_count = 1
    expected_domain = 'www.google-analytics.com'

    domain_summary = get_domains_per_directive(data)

    assert 1 == len(domain_summary.keys())
    assert expected_directive in domain_summary.keys()
    assert len(domain_summary[expected_directive]) == expected_domain_count
    assert domain_summary[expected_directive][0] == expected_domain


def test_reported_ok_no_unsafe_inline():
    expected_result = False
    csp = {'default-src': {
        'keywords': ['self'],
        'domains': ['www.google.com'],
        'data': []
    }
    }
    unsafe_without_domains = check_unsafe_inline_used_without_domains(csp)

    assert expected_result == unsafe_without_domains


def test_reported_ok_unsafe_inline_with_domains():
    expected_result = False
    csp = {'default-src': {
                'keywords': ['unsafe-inline'],
                'domains': ['www.google.com'],
                'data': []
            }
    }
    unsafe_without_domains = check_unsafe_inline_used_without_domains(csp)
    assert expected_result == unsafe_without_domains


def test_reported_found_unsafe_inline_without_domains():
    expected_result = True
    csp = {'default-src': {
        'keywords': ['unsafe-inline'],
        'domains': [],
        'data': []
    }
    }
    unsafe_without_domains = check_unsafe_inline_used_without_domains(csp)
    assert expected_result == unsafe_without_domains


def test_extract_domains_unsafe_inline_from_data_entries():
    data = [
        "repo1,file1,default-src 'self' 'unsafe-inline' www.google-analytics.com data:,'0','1','0'",
    ]
    keyword = 'unsafe-inline'
    analysis_entries = extract_policies_without_domains(keyword, data)

    assert 0 == len(analysis_entries)


def test_extract_policies_with_missing_domains_with_unsafe_inline_from_data_entries():
    data = [
        "repo1,file1,default-src 'self' 'unsafe-inline' data:,'0','1','0'",
    ]
    keyword = 'unsafe-inline'
    analysis_entries = extract_policies_without_domains(keyword, data)

    assert 1 == len(analysis_entries)
    entry = analysis_entries[0].rstrip('\n')
    parts = entry.split(',')
    assert 3 == len(parts)
    assert 'repo1' == parts[0]
    assert 'file1' == parts[1].lstrip()
    assert "default-src 'self' 'unsafe-inline' data:" == parts[2].lstrip()


def test_reported_ok_no_unsafe_eval():
    expected_result = False
    csp = {'default-src': {
        'keywords': ['self'],
        'domains': ['www.google.com'],
        'data': []
    }
    }
    unsafe_without_domains = check_keyword_used_without_domains('unsafe-eval', csp)

    assert expected_result == unsafe_without_domains


def test_reported_ok_unsafe_eval_with_domains():
    expected_result = False
    csp = {'default-src': {
        'keywords': ['unsafe-eval'],
        'domains': ['www.google.com'],
        'data': []
    }
    }
    unsafe_without_domains = check_keyword_used_without_domains('unsafe-eval', csp)
    assert expected_result == unsafe_without_domains


def test_reported_found_unsafe_eval_without_domains():
    expected_result = True
    csp = {'default-src': {
        'keywords': ['unsafe-eval'],
        'domains': [],
        'data': []
    }
    }
    unsafe_without_domains = check_keyword_used_without_domains('unsafe-eval', csp)
    assert expected_result == unsafe_without_domains


def test_extract_domains_unsafe_eval_from_data_entries():
    data = [
        "repo1,file1,default-src 'self' 'unsafe-eval' www.google-analytics.com data:,'0','1','0'",
    ]
    keyword = 'unsafe-eval'
    analysis_entries = extract_policies_without_domains(keyword, data)

    assert 0 == len(analysis_entries)


def test_extract_policies_with_missing_domains_with_domains_unsafe_eval_from_data_entries():
    data = [
        "repo1,file1,default-src 'self' 'unsafe-eval' data:,'0','1','0'",
    ]
    keyword = 'unsafe-eval'
    analysis_entries = extract_policies_without_domains(keyword, data)

    assert 1 == len(analysis_entries)
    entry = analysis_entries[0].rstrip('\n')
    parts = entry.split(',')
    assert 3 == len(parts)
    assert 'repo1' == parts[0]
    assert 'file1' == parts[1].lstrip()
    assert "default-src 'self' 'unsafe-eval' data:" == parts[2].lstrip()

