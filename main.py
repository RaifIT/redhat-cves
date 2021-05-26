import requests
import json
import csv

base_url = "https://access.redhat.com/hydra/rest/securitydata"


'''Query API with specified parameters
Returns JSON http response'''
def query_api(params):
    url = base_url + '/cve.json'
    response = requests.get(url, params=params)
    return response


'''Get the CVEs in a specified date range from start_date to end_date as a dictionary
Returns dict of the JSON response'''
def get_cves_between_dict(start_date, end_date):
    return json.loads(get_cves_between(start_date, end_date))


'''Get the CVEs in a specified date range from start_date to end_date as a JSON
Returns content of the JSON response'''
def get_cves_between(start_date, end_date):
    response = query_api({'after': start_date, 'before': end_date})
    return response.content


'''Write a python dictionary to a CSV file named name.csv'''
def write_dict_list_to_csv(dict_list, name):
    keys = dict_list[0].keys()
    with open(name+'.csv', 'w', newline='')  as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(dict_list)


'''Convert a regular API response dict into a dict that groups public_date keys with a list of CVEs
Returns a dictionary of {public_date: [{bugzilla_description, CVE}, {},...]}'''
def dict_list_to_timed_dict_list(dict_list):
    timed_dict_list = {}
    for dict in dict_list:
        entry = {'bugzilla_description': dict['bugzilla_description'], 'CVE': dict['CVE']}
        if dict['public_date'] in timed_dict_list.keys():
            timed_dict_list[dict['public_date']].append(entry)
        else:
            timed_dict_list[dict['public_date']] = [entry]
    return timed_dict_list


'''Returns the number of CVEs in a single entry of a timed_dict. i.e. the number of CVEs on a specific date'''
def count_cves(timed_dict_entry):
    cves = get_cves(timed_dict_entry)
    return len(cves)


'''Returns a set of CVEs a single entry of a timed_dict. i.e. the unique CVEs on a specific date'''
def get_cves(timed_dict_entry):
    cves = set()
    for dict in timed_dict_entry:
        cves.add(dict['CVE'])
    return cves


'''Aggregate the results in a timed_dict by date
Returns a list of dictionaries of {public_date, cve_count}'''
def aggregate_timed_dict(timed_dict):
    aggregated_dict = []
    for public_date, dict in timed_dict.items():
        aggregated_dict.append({'public_date': public_date, 'cve_count': count_cves(dict)})
    return aggregated_dict


'''Write the list of {public_date, cve_count} to a CSV file named aggregated.csv'''
def aggregated_to_csv(aggregated_dict):
    with open('cves.csv', 'w', newline='')  as output_file:
        csv


def test():
    start = '2021-01-01'
    end = '2021-12-30'
    content = get_cves_between(start, end)
    with open('cves.json', 'wb') as outf:
        outf.write(content)
    json_dicts = json.loads(content)
    vuls = []
    # print(len(json_dicts))
    # print(json_dicts[0].keys())
    # print(json_dicts[0])
    # print(json_dicts[0]['CVE'])
    for vul in json_dicts:
        # print(vul['public_date'], vul['CVE'], vul['bugzilla_description'])
        vuls.append(
            {'public_date': vul['public_date'], 'bugzilla_description': vul['bugzilla_description'], 'CVE': vul['CVE']})
    # print(vuls)
    write_dict_list_to_csv(vuls, 'cves')
    timed_dict = dict_list_to_timed_dict_list(vuls)
    # print(timed_dict)
    # print(timed_dict.keys())
    print(timed_dict['2021-05-25T00:00:00Z'])
    print(get_cves(timed_dict['2021-05-25T00:00:00Z']))
    print(count_cves(timed_dict['2021-05-25T00:00:00Z']))
    print(aggregate_timed_dict(timed_dict))
    print(aggregate_timed_dict(timed_dict)[0])
    print(aggregate_timed_dict(timed_dict)[0].keys())
    write_dict_list_to_csv(aggregate_timed_dict(timed_dict), 'aggregated')

test()
