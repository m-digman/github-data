from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from github_config import github_config
from datetime import datetime
import os
import csv

gh_config = github_config()

csv_column = ["Repository", "Dependency", "From", "Status", "Severity", "CVSS", "Summary", "Affected Versions", "Patched Version", "Current Version", "Published", "Link", "Dismisser", "Reason", "Closed"]

gql_query = """
        query MyQuery ($repository: String!, $owner: String!) {
            repository(name: $repository, owner: $owner) {
                id
                name
                vulnerabilityAlerts(first: 50) {
                    nodes {
                        dismissedAt
                        dismisser {
                            login
                            name
                        }
                        dismissReason
                        securityVulnerability {
                            advisory {
                                cvss {
                                    score
                                }
                                permalink
                                summary
                                publishedAt
                            }
                            firstPatchedVersion {
                                identifier
                            }
                            package {
                                name
                            }
                            severity
                            vulnerableVersionRange
                        }
                        vulnerableManifestFilename
                        vulnerableRequirements
                    }
                }
            }
        }
    """


def create_folder(path):
    if not os.path.exists(path):
        os.makedirs(path)


def create_csv(rows):
    today = datetime.now()
    path = ".//data//"
    create_folder(path)

    filename = "{0}//security-alerts-{1:%Y-%m-%d}.csv".format(path, today)
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(csv_column)
        writer.writerows(rows)

    print("Extracted {0} vulnerabilities to \"{1}\"".format(len(rows), filename))


def get_date_from_utc_string(date_string):
    if date_string:
        # 2021-07-20T14:54:42Z
        return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%SZ").date()


def extract_data(repo_name, data_node, data_rows):
    severity = data_node["securityVulnerability"]["severity"]
    cvss_score = data_node["securityVulnerability"]["advisory"]["cvss"]["score"]
    summary = data_node["securityVulnerability"]["advisory"]["summary"]
    link = data_node["securityVulnerability"]["advisory"]["permalink"]
    date_published = get_date_from_utc_string(data_node["securityVulnerability"]["advisory"]["publishedAt"])
    dependency = data_node["securityVulnerability"]["package"]["name"]
    fix = data_node["securityVulnerability"]["firstPatchedVersion"]
    patched_version = ""
    if fix:
        patched_version = fix["identifier"]
    affected_version = data_node["securityVulnerability"]["vulnerableVersionRange"]
    current_version = data_node["vulnerableRequirements"]
    manifest = data_node["vulnerableManifestFilename"]
    dismiss_reason = data_node["dismissReason"]
    dismisser, date_closed = "", ""
    status = "Open"
    if dismiss_reason:
        status = "Closed"
        dismisser = "{0} ({1})".format(data_node["dismisser"]["name"], data_node["dismisser"]["login"])
        date_closed = get_date_from_utc_string(data_node["dismissedAt"])

    return [repo_name, dependency, manifest, status, severity, cvss_score, summary, affected_version, patched_version, current_version,
            date_published, link, dismisser, dismiss_reason, date_closed]


def get_repo_vulnerabilities(repository):
    token = "Bearer {0}".format(gh_config.access_token)
    transport = AIOHTTPTransport(url="https://api.github.com/graphql", headers={'Authorization': token})
    client = Client(transport=transport, fetch_schema_from_transport=True)

    query = gql(gql_query)
    params = {"repository": repository, "owner": gh_config.owner}
    return client.execute(query, variable_values=params)


def main():
    csv_rows = []

    for repo_name in gh_config.repositories:
        data = get_repo_vulnerabilities(repo_name)

        for node in data["repository"]["vulnerabilityAlerts"]["nodes"]:
            vulnerability = extract_data(repo_name, node, csv_rows)
            csv_rows.append(vulnerability)

    create_csv(csv_rows)


if __name__ == "__main__":
    main()