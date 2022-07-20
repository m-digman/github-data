from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from github_config import github_config
from datetime import datetime
import os
import csv

gh_config = github_config()

csv_column = ["Repository", "Language", "Dependency", "From", "Status", "Severity", "CVSS", "Summary", "Upgrade", "Diff", "Affected Versions", "Patched Version", "Current Version", "Published", "Link", "Dismisser", "Reason", "Closed"]

gql_query = """
        query MyQuery ($repository: String!, $owner: String!) {
            repository(name: $repository, owner: $owner) {
                id
                name
                primaryLanguage {
                    name
                }
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
                        vulnerableManifestPath
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


def get_version_int(version_string):
    # "0-20180910192245-6acdf747ae99"
    index = version_string.find("-")
    if index == -1:
        return int(version_string)
    else:
        return int(version_string[0:index])


def get_semantic_versions(version):
    versions = version.split(".")
    return get_version_int(versions[0]), get_version_int(versions[1]), get_version_int(versions[2])


def get_upgrade_status(current_version, patched_version):
    if current_version and patched_version:
        current_major, current_minor, current_patch = get_semantic_versions(current_version)
        patched_major, patched_minor, patched_patch = get_semantic_versions(patched_version)

        if patched_major > current_major:
            return "Major", patched_major - current_major
        elif patched_major == current_major and patched_minor > current_minor:
            return "Minor", patched_minor - current_minor
        elif patched_major == current_major and patched_minor == current_minor and patched_patch > current_patch:
            return "Patch", patched_patch - current_patch

    return "", ""


def strip_semantic_version(version_string):
    # "= 1.2.3" or "= v1.2.3" or "= v0.0.0-20180910192245-6acdf747ae99"
    if version_string:
        if "v" in version_string:
            version_string = version_string.replace("v", "")

        if version_string.startswith("="):
            return version_string.replace("= ", "")

    return version_string


def get_date_from_utc_string(date_string):
    if date_string:
        # 2021-07-20T14:54:42Z
        return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%SZ").date()


def extract_data(repo_name, language, data_node):
    severity = data_node["securityVulnerability"]["severity"]
    cvss_score = data_node["securityVulnerability"]["advisory"]["cvss"]["score"]
    summary = data_node["securityVulnerability"]["advisory"]["summary"].strip()
    link = data_node["securityVulnerability"]["advisory"]["permalink"]
    date_published = get_date_from_utc_string(data_node["securityVulnerability"]["advisory"]["publishedAt"])
    dependency = data_node["securityVulnerability"]["package"]["name"]
    fix = data_node["securityVulnerability"]["firstPatchedVersion"]
    patched_version = ""
    if fix:
        patched_version = fix["identifier"]
    affected_version = data_node["securityVulnerability"]["vulnerableVersionRange"]
    current_version = strip_semantic_version(data_node["vulnerableRequirements"])
    manifest = data_node["vulnerableManifestPath"]
    dismiss_reason = data_node["dismissReason"]
    dismisser, date_closed = "", ""
    status = "Open"
    if dismiss_reason:
        status = "Closed"
        dismisser = "{0} ({1})".format(data_node["dismisser"]["name"], data_node["dismisser"]["login"])
        date_closed = get_date_from_utc_string(data_node["dismissedAt"])

    upgrade_type, upgrade_difference = get_upgrade_status(current_version, patched_version)

    return [repo_name, language, dependency, manifest, status, severity, cvss_score, summary, upgrade_type, upgrade_difference,
            affected_version, patched_version, current_version, date_published, link, dismisser, dismiss_reason, date_closed]


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
        print("Processing \"{0}\" ...".format(repo_name))

        data = get_repo_vulnerabilities(repo_name)
        language = data["repository"]["primaryLanguage"]["name"]

        for node in data["repository"]["vulnerabilityAlerts"]["nodes"]:
            vulnerability = extract_data(repo_name, language, node)
            csv_rows.append(vulnerability)

    if len(csv_rows) > 0:
        create_csv(csv_rows)


if __name__ == "__main__":
    main()