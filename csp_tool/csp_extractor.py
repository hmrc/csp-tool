import base64

base64_csp_prefixes = [
    'play.filters.headers.contentSecurityPolicy.base64',
]

csp_prefixes = [
    'play.filters.headers.contentSecurityPolicy.base64',
    'play.filters.headers.contentSecurityPolicy',
    'play.filters.headers.contentSecurity',
    'filters.headers.security.contentSecurityPolicy',
    'filters.headers.security.contentSecurity',
    # todo, better tests for this
    'filters.headers.contentSecurityPolicy',
    'filters.headers.contentSecurity',
    'headers.contentSecurityPolicy',

    # todo better tests for this
    'contentSecurityPolicy',
    'contentSecurity'
    ]


def extract_csp_part_from_java_like_entry(entry: str):
    if entry.startswith('-J') or entry.startswith('-j'):
        entry = entry[2:]

    sep = ''

    if entry.startswith('-d'):
        sep = '-d'
    elif entry.startswith('-D'):
        sep = '-D'
    else:
        # not sophisticated to handle it yet, mark for bad data
        return None

    sanitised_entry = None

    # do some clean up now
    entry = entry.rstrip(',').rstrip('"')

    parts = entry.split(sep)

    found = False

    for part in parts:
        if not found:
            part = part.strip()
            for prefix in csp_prefixes:
                if not found:
                    if part.startswith(prefix):
                        csp_parts = part.split('=')
                        sanitised_entry = csp_parts[1].strip("\'")
                        found == True
                else:
                    break
        else:
            break
    if is_base64_like(sanitised_entry):
        return f'base64: {sanitised_entry}'
    return sanitised_entry


def decode_base64_entry(entry: str):
    try:
        bytes = base64.b64decode(entry)
        return bytes.decode('utf-8')

    except Exception as e:
        return None


def is_base64_like(entry: str):
    return len(entry) > 30 and entry.find(' ') == -1


def extract_full_csp(entry: str):

    # handle -D flags more flexibly, the csp is not always the first in the line
    if '-D' in entry:
        index = entry.find('-D')
        entry = entry[index:]
    java_like_prefixes = ['-J' ,'-d' ,'-j', '-D']
    for j_prefix in java_like_prefixes:
        if entry.startswith(j_prefix):
            return extract_csp_part_from_java_like_entry(entry)

    entry = entry.strip().lstrip('#').lstrip('/').lstrip().strip('"')

    # for base64 in base64_csp_prefixes:
    #     if entry.startswith(base64):
    #         return 'base64'

    start_index = 0

    for prefix in csp_prefixes:
        if entry.startswith(prefix):
            start_index = len(prefix)
            break

    if start_index == 0:
        return None

    csp = entry[start_index:]
    csp = csp.strip().lstrip(':').lstrip().lstrip('=').lstrip().rstrip(',').strip('"')

    # could still be a base64 encoded string.
    # NAIVE check: check if it is longer than longest directive and contains no spaces
    if is_base64_like(csp):
        return f'base64: {csp}'

    return csp


