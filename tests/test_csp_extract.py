import pytest
from csp_tool.csp_extractor import extract_csp_part_from_java_like_entry, extract_full_csp, decode_base64_entry


def test_can_decode_base64_entry():
    plain = "default-src 'self' 'unsafe-inline' 'unsafe-eval' www.googletagmanager.com www.google-analytics.com tagmanager.google.com fonts.googleapis.com ssl.gstatic.com www.gstatic.com fonts.gstatic.com fonts.googleapis.com data:;"
    base_64_csp = 'ZGVmYXVsdC1zcmMgJ3NlbGYnICd1bnNhZmUtaW5saW5lJyAndW5zYWZlLWV2YWwnIHd3dy5nb29nbGV0YWdtYW5hZ2VyLmNvbSB3d3cuZ29vZ2xlLWFuYWx5dGljcy5jb20gdGFnbWFuYWdlci5nb29nbGUuY29tIGZvbnRzLmdvb2dsZWFwaXMuY29tIHNzbC5nc3RhdGljLmNvbSB3d3cuZ3N0YXRpYy5jb20gZm9udHMuZ3N0YXRpYy5jb20gZm9udHMuZ29vZ2xlYXBpcy5jb20gZGF0YTo7'
    decoded = decode_base64_entry(base_64_csp)

    assert plain == decoded


def test_can_extract_csp_pair_from_java_like_string():
    java_like = "-J-Dapplication.router=testOnlyDoNotUseInAppConf.Routes -Dhttp.port=9284 -Dplay.filters.headers.contentSecurityPolicy='www.google-analytics.com'"
    expected_extracted_value = "www.google-analytics.com"

    assert expected_extracted_value == extract_csp_part_from_java_like_entry(java_like)


def test_highlights_base64_csp_strings():
    base_64_csp = 'play.filters.headers.contentSecurityPolicy.base64 = "ZGVmYXVsdC1zcmMgJ3NlbGYnICd1bnNhZmUtaW5saW5lJyAndW5zYWZlLWV2YWwnIHd3dy5nb29nbGV0YWdtYW5hZ2VyLmNvbSB3d3cuZ29vZ2xlLWFuYWx5dGljcy5jb20gdGFnbWFuYWdlci5nb29nbGUuY29tIGZvbnRzLmdvb2dsZWFwaXMuY29tIHNzbC5nc3RhdGljLmNvbSB3d3cuZ3N0YXRpYy5jb20gZm9udHMuZ3N0YXRpYy5jb20gZm9udHMuZ29vZ2xlYXBpcy5jb20gZGF0YTo7"'
    expected_return = 'base64: ' + 'ZGVmYXVsdC1zcmMgJ3NlbGYnICd1bnNhZmUtaW5saW5lJyAndW5zYWZlLWV2YWwnIHd3dy5nb29nbGV0YWdtYW5hZ2VyLmNvbSB3d3cuZ29vZ2xlLWFuYWx5dGljcy5jb20gdGFnbWFuYWdlci5nb29nbGUuY29tIGZvbnRzLmdvb2dsZWFwaXMuY29tIHNzbC5nc3RhdGljLmNvbSB3d3cuZ3N0YXRpYy5jb20gZm9udHMuZ3N0YXRpYy5jb20gZm9udHMuZ29vZ2xlYXBpcy5jb20gZGF0YTo7'

    assert expected_return == extract_full_csp(base_64_csp)


def test_highlights_base64_csp_strings_without_prefix():
    base_64_csp = 'contentSecurityPolicy ZGVmYXVsdC1zcmMgJ3NlbGYnICd1bnNhZmUtaW5saW5lJyAndW5zYWZlLWV2YWwnIHd3dy5nb29nbGV0YWdtYW5hZ2VyLmNvbSB3d3cuZ29vZ2xlLWFuYWx5dGljcy5jb20gdGFnbWFuYWdlci5nb29nbGUuY29tIGZvbnRzLmdvb2dsZWFwaXMuY29tIHNzbC5nc3RhdGljLmNvbSB3d3cuZ3N0YXRpYy5jb20gZm9udHMuZ3N0YXRpYy5jb20gZm9udHMuZ29vZ2xlYXBpcy5jb20gZGF0YTo7'
    expected_return = 'base64: ' + 'ZGVmYXVsdC1zcmMgJ3NlbGYnICd1bnNhZmUtaW5saW5lJyAndW5zYWZlLWV2YWwnIHd3dy5nb29nbGV0YWdtYW5hZ2VyLmNvbSB3d3cuZ29vZ2xlLWFuYWx5dGljcy5jb20gdGFnbWFuYWdlci5nb29nbGUuY29tIGZvbnRzLmdvb2dsZWFwaXMuY29tIHNzbC5nc3RhdGljLmNvbSB3d3cuZ3N0YXRpYy5jb20gZm9udHMuZ3N0YXRpYy5jb20gZm9udHMuZ29vZ2xlYXBpcy5jb20gZGF0YTo7'

    assert expected_return == extract_full_csp(base_64_csp)


@pytest.mark.parametrize(
    "entry,expected_csp",
    [
        ('something unexpected', None),
        ("-J-Dapplication.router=testOnlyDoNotUseInAppConf.Routes -Dhttp.port=9284 -Dplay.filters.headers.contentSecurityPolicy='www.google-analytics.com'", "www.google-analytics.com"),
        ('        "-Dplay.filters.headers.contentSecurityPolicy='+"'www.google-analytics.com'","www.google-analytics.com"),
        ("contentSecurity default-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.googletagmanager.com https://www.google-analytics.com https://tagmanager.google.com https://fonts.googleapis.com https://ssl.gstatic.com https://www.gstatic.com https://fonts.gstatic.com https://fonts.googleapis.com data:;", "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.googletagmanager.com https://www.google-analytics.com https://tagmanager.google.com https://fonts.googleapis.com https://ssl.gstatic.com https://www.gstatic.com https://fonts.gstatic.com https://fonts.googleapis.com data:;"),
        ("filters.headers.security.contentSecurity default-src 'self' 'unsafe-inline' 'unsafe-eval' webchat.tax.service.gov.uk *.analytics-egain.com https://www.googletagmanager.com https://www.google-analytics.com https://tagmanager.google.com https://fonts.googleapis.com https://ssl.gstatic.com https://www.gstatic.com https://fonts.gstatic.com https://fonts.googleapis.com data:","default-src 'self' 'unsafe-inline' 'unsafe-eval' webchat.tax.service.gov.uk *.analytics-egain.com https://www.googletagmanager.com https://www.google-analytics.com https://tagmanager.google.com https://fonts.googleapis.com https://ssl.gstatic.com https://www.gstatic.com https://fonts.gstatic.com https://fonts.googleapis.com data:"),
        ("#filters.headers.contentSecurity default-src 'self' 'unsafe-inline' localhost:9000 localhost:9032 localhost:9250 stats.g.doubleclick.net www.google-analytics.com object-src 'none'","default-src 'self' 'unsafe-inline' localhost:9000 localhost:9032 localhost:9250 stats.g.doubleclick.net www.google-analytics.com object-src 'none'"),
        ("play.filters.headers.contentSecurity default-src 'self' 'unsafe-inline' www.google-analytics.com app.optimizely.com cdn.optimizely.com *.optimizely.com optimizely.s3.amazonaws.com data:", "default-src 'self' 'unsafe-inline' www.google-analytics.com app.optimizely.com cdn.optimizely.com *.optimizely.com optimizely.s3.amazonaws.com data:"),
        ('play.filters.headers.contentSecurityPolicy: "default-src"', 'default-src'),
        ('play.filters.headers.contentSecurityPolicy: "ZGVmYXVsdC1zcmMgJ3NlbGYnICd1bnNhZmUtaW5saW5lJyAndW5zYWZlLWV2YWwn"', 'base64: ' + 'ZGVmYXVsdC1zcmMgJ3NlbGYnICd1bnNhZmUtaW5saW5lJyAndW5zYWZlLWV2YWwn'),
        ("headers.contentSecurityPolicy= \"default-src 'self' 'unsafe-inline' analytics.analytics-egain.com localhost:9032 localhost:9310 *.optimizely.com optimizely.s3.amazonaws.com www.google-analytics.com www.googletagmanager.com fonts.googleapis.com tagmanager.google.com ssl.gstatic.com www.gstatic.com fonts.gstatic.com data:\"", "default-src 'self' 'unsafe-inline' analytics.analytics-egain.com localhost:9032 localhost:9310 *.optimizely.com optimizely.s3.amazonaws.com www.google-analytics.com www.googletagmanager.com fonts.googleapis.com tagmanager.google.com ssl.gstatic.com www.gstatic.com fonts.gstatic.com data:"),
        ("//play.filters.headers.contentSecurityPolicy = \"default-src 'self' localhost:9000 localhost:9032 localhost:9250 www.google-analytics.com\"", "default-src 'self' localhost:9000 localhost:9032 localhost:9250 www.google-analytics.com"),
    ],
)
def test_extract_csp_from_entry(entry, expected_csp):
    csp = extract_full_csp(entry)
    assert expected_csp == csp