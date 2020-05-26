from .csp_object import valid_directives, valid_keywords


def parse_csp(csp_string: str):
    if csp_string is not None and csp_string != '':
        csp = {}
        scopes = csp_string.split(';')
        for scope in scopes:
            if scope == '':
                continue  # nothing useful found
            elements = scope.split()
            directive = elements[0]
            if directive not in valid_directives:
                # exclude as this is bad data; or misuse
                continue
            sub_elements = {
                'keywords': [],
                'domains': [],
                'data': []
            }

            data_mode = False
            for el in elements[1:]:
                el = el.strip('\'').strip('"')
                if data_mode:
                    if el is not None and el != '':
                        sub_elements['data'].append(el)
                else:
                    if el in valid_keywords:
                        sub_elements['keywords'].append(el)
                    elif el == 'data:':
                        data_mode = True
                        continue
                    elif el is not None and el != '':
                        sub_elements['domains'].append(el)

            csp[directive] = sub_elements

        # todo validate the csp more fully and return valid,csp as tuple


        return csp

    return None


def bulk_parse_csp(entries: [str]):
    csps = []

    for entry in entries:
        csp = parse_csp(entry)
        if csp is not None:
            csps.append(csp)

    return csps




