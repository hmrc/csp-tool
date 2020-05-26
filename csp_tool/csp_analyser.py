import os
import pandas as pd
from pandas import DataFrame

from .csp_extractor import extract_full_csp
from .csp_parser import bulk_parse_csp, parse_csp


def initialise_data_frame(data: [str], headers: [str]):
    from io import StringIO

    import_data = []
    import_data.append(','.join(headers))
    import_data.extend(data)

    string_data = StringIO('\n'.join(import_data))
    df = pd.read_csv(string_data)
    return df


def extract_output_array_from_df_group(df_group: DataFrame, active_only: bool):
    entries = []

    # todo this code assumes that repo will be an available header / field in the group
    #  check this exists or work with something passed through
    if active_only:
        for entry, count in df_group.repo.items():
            if entry == 1:
                entries.append(f"{count} found\n")
                return entries

    for entry, count in df_group.repo.items():  # grabs an existing index to pull the grouped series results
        if entry == 0:
            entry = 'not in group'
        elif entry == 1:
            entry == 'in group'
        entries.append(f"{count} x {entry}\n")

    return entries


def rollup_data_by_header(data: [str], header: str, active_only: bool, headers: [str]):
    df = initialise_data_frame(data, headers)
    gp = df.groupby(header).count()

    return extract_output_array_from_df_group(gp, active_only)


def get_domains_per_directive_from_csps(csps: [dict]):
    domains = {}

    for csp in csps:
        for key in csp.keys():
            if 'domains' in csp[key].keys():
                if len(csp[key]['domains']) > 0:
                    if key not in domains.keys():
                        domains[key] = csp[key]['domains']
                    else:
                        for domain in csp[key]['domains']:
                            if domain not in domains[key]:
                                domains[key].append(domain)

    return domains


def get_domains_per_directive_from_csp_strings(csp_strings: [str]):
    csps = bulk_parse_csp(csp_strings)
    return get_domains_per_directive_from_csps(csps)



    '''Expects entries to be of the form
    repo_name, file_name, csp_policy
    '''
def get_domains_per_directive(data_entries: [str]):

    csp_strings = []
    for entry in data_entries:
        parts = entry.split(',')
        csp_strings.append(parts[2])

    return get_domains_per_directive_from_csp_strings(csp_strings)


def check_keyword_used_without_domains(keyword: str, csp: dict):
    if keyword in ['self', 'None']:
        # domains don't apply here
        return False
    for directive in csp.keys():
        if keyword in csp[directive]['keywords']:
            if len(csp[directive]['domains']) == 0:
                return True
    # could be rewritten to use filter or dropwhile from itertools
    return False


def check_unsafe_inline_used_without_domains(csp: dict):
    return check_keyword_used_without_domains('unsafe-inline', csp)


def extract_policies_without_domains(keyword: str, data_entries: [str]):
    policy_records = []
    for entry in data_entries:
        parts = entry.split(',')
        csp = parse_csp(parts[2])
        if check_keyword_used_without_domains(keyword, csp):
            policy_records.append(f'{parts[0]}, {parts[1]}, {parts[2]}\n')

    return policy_records


def extract_policies_using_localhost(data_entries: [str]):
    policy_records = []
    for entry in data_entries:
        parts = entry.split(',')
        csp = parts[2]
        if 'localhost' in csp:
            policy_records.append(f'{parts[0]}, {parts[1]}, {parts[2]}\n')

    return policy_records


