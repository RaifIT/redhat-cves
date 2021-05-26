import requests
import json
import csv

base_url = "https://access.redhat.com/hydra/rest/securitydata"

def query_api(params):
    url = base_url + '/cve.json'
    response = requests.get(url, params=params)
    return response

def get_cves_between_dict(start_date, end_date):
    response = query_api({'after':start_date, 'before':end_date})
    dict_response = json.loads(response.content)
    return dict_response

def get_cves_between(start_date, end_date):
    response = query_api({'after':start_date, 'before':end_date})
    return response.content


def write_dict_list_to_csv(dict_list):
    keys = dict_list[0].keys()
    with open('cves.csv', 'w', newline='')  as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(dict_list)

def dict_list_to_timed_dict_list(dict_list):
    timed_dict_list = {}
    for dict in dict_list:
        entry = {'bugzilla_description': dict['bugzilla_description'], 'CVE': dict['CVE']}
        if dict['public_date'] in timed_dict_list.keys():
            timed_dict_list[dict['public_date']].append(entry)
        else:
            timed_dict_list[dict['public_date']] = [entry]
    return timed_dict_list

def count_cves(timed_dict_entry):
    cves = get_cves(timed_dict_entry)
    return len(cves)


def get_cves(timed_dict_entry):
    cves = set()
    for dict in timed_dict_entry:
        cves.add(dict['CVE'])
    return cves


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
        #print(vul['public_date'], vul['CVE'], vul['bugzilla_description'])
        vuls.append({'public_date':vul['public_date'], 'bugzilla_description':vul['bugzilla_description'], 'CVE': vul['CVE']})
    #print(vuls)
    write_dict_list_to_csv(vuls)
    timed_dict = dict_list_to_timed_dict_list(vuls)
    #print(timed_dict)
    #print(timed_dict.keys())
    print(timed_dict['2021-05-25T00:00:00Z'])
    print(get_cves(timed_dict['2021-05-25T00:00:00Z']))
    print(count_cves(timed_dict['2021-05-25T00:00:00Z']))


test()