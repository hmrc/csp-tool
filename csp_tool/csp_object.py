
class CSPDirective:
    name = None
    keywords = []
    data_uris = []
    domains = []

    def __init__(self, name: str):
        if name in valid_directives:
            self.name = name
        else:
            raise Exception("Unable to create directive")


class CSPDefaultDirective(CSPDirective):

    def __init__(self):
        super().__init__(self, 'default-src')

    sub_directives = []


class ContentSecurityPolicy:
    directives = []


class ContentSecurityPolicyReview:
    policy = ContentSecurityPolicy()
    warnings = []

    def contains_localhost(self):
        return True


valid_directives = [
    'default-src',
    'base-uri',
    'form-action',
    'frame-ancestors',
    'plugin-types',
    'report-uri',
    'sandbox',
    'child-src',
    'connect-src',
    'font-src',
    'frame-src',
    'img-src',
    'media-src',
    'object-src',
    'style-src',
    'upgrade-insecure-requests',
    'worker-src',
]

valid_keywords = ['self', 'unsafe-inline', 'unsafe-eval', 'none', 'unsafe-url']

specialist_keywords = ['unsafe-inline', 'unsafe-eval', 'unsafe-url']

# nonces e.g. Content-Security-Policy: script-src 'nonce-EDNnf03nceIOfn39fn3e9h3sdfa'
# (changed per request and unguessable)
nonce_prefix = 'nonce-'

# hashes e.g. Content-Security-Policy: script-src 'sha256-qznLcsROx4GACP2dm0UCKCzCG-HiZ1guq6ZZDob_Tng='
# script without script tags is taken and hashed on server side then passed into Content-Security-Policy header
valid_hash_prefixes = [
    'sha256-',
    'sha384-',
    'sha512-',
]