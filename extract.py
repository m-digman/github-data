from github import Github, GithubException
from github.Repository import Repository
from github_config import github_config
from datetime import datetime
from enum import Enum, auto
import os
import csv

gh_config = github_config()

csv_repo_columns = ["Name", "Type", "Topics", "SonarCloud", "Workflow", "Dependabot", "Created", "Last Commit", "Diff (days)", "Admin/Creator", "Workflows", "Branches", "Default", "Merge Button", "Auto Delete Branch", "Protections", "No. Contributers", "Contributers"]
csv_branch_columns = ["Repository", "Branch", "Is Default", "Last Commit", "By"]

LOG_VALUES = "{0} ({1})"

users_cache = {}

class Columns(Enum):
    REPOS = auto()
    BRANCHES = auto()


def create_folder(path):
    if not os.path.exists(path):
        os.makedirs(path)


def create_csv(rows, column_type):
    today = datetime.now()
    path = ".//data//"
    create_folder(path)

    csv_columns = csv_repo_columns
    if Columns.BRANCHES == column_type:
        csv_columns = csv_branch_columns

    filename = "{0}//private-{1}-{2:%Y-%m-%d}.csv".format(path, column_type.name.lower(), today)
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(csv_columns)
        writer.writerows(rows)

    print("Extracted {0} {1} to \"{2}\"".format(len(rows), column_type.name.lower(), filename))


def get_user_details(user_login):
    user_details = users_cache.get(user_login)
    if user_details is not None:
        return user_details

    g = Github(gh_config.access_token)
    user = g.get_user(login=user_login)

    if user.name == None:
        user_details = user_login
    else:
        user_details = LOG_VALUES.format(user_login, user.name.strip())

    # Cache users to reduce api calls
    users_cache[user_login] = user_details
    return user_details


def get_administrators(repository: Repository):
    administrators = ""

    collaborators_data = repository.get_collaborators(affiliation='direct')
    if collaborators_data:
        for collab in collaborators_data:
            if collab.permissions.admin and len(administrators) > 0:
                administrators = administrators + ", " + get_user_details(collab.login)
            else:
                administrators = get_user_details(collab.login)
    
    return administrators


def get_contributers(repository: Repository):
    contrib_count = 0
    contributors = ""

    contributor_stats_data = repository.get_stats_contributors()
    if contributor_stats_data:
        for contrib in contributor_stats_data:
            contrib_count += 1

            author = get_user_details(contrib.author.login)

            if len(contributors) > 0:
                contributors = contributors + ", " + author
            else:
                contributors = author
    
    return contrib_count, contributors


def get_commit_authors_since_created(repository: Repository):
    contrib_count = 0
    contributors = ""

    try:
        commits_data = repository.get_commits(since=repository.created_at)
        contrib_count = commits_data.totalCount
        for commit in commits_data:
            author = commit.commit.author.name
            email = commit.commit.author.email
            if len(author) > 0 and author not in contributors:
                if len(contributors) > 0:
                    contributors = "{0}, {1} ({2})".format(contributors, email, author)
                else:
                    contributors = LOG_VALUES.format(email, author)
    except GithubException as error:
        print(error)

    return contrib_count, contributors


def get_last_commit_date(repository: Repository):
    try:
        commits_data = repository.get_commits()
        if commits_data.totalCount > 0:
            return commits_data[0].commit.author.date
    except GithubException as error:
        print(error)

    return None


def get_default_branch_protections(repository: Repository):
    try:
        status_checks = repository.get_branch(repository.default_branch).get_protection().required_status_checks
        if status_checks:
            return ", ".join(status_checks.contexts)
    except GithubException:
        pass

    return ""


def get_workflows(repository: Repository):
    workflows = ""
    try:
        for workflow in repository.get_workflows():
            if workflow.state == "active":
                if len(workflows) > 0:
                    workflows = workflows + ", " + workflow.name
                else:
                    workflows = workflow.name
    except GithubException:
        pass

    return workflows


def get_merge_button_rules(repository: Repository):
    merge_button = ""

    if repository.allow_merge_commit:
        merge_button = "[Merge]"
    if repository.allow_rebase_merge:
        merge_button = merge_button + "[Rebase]"
    if repository.allow_squash_merge:
        merge_button = merge_button + "[Squash]"

    return merge_button


def contains_string(string, find_string):
    if len(find_string) > 0 and find_string in string:
        return "Yes"
    
    return ""


def get_repo_type(repository: Repository):
    repo_type = "Private"
    if not repository.private:
        repo_type = "Public"
    if repository.archived:
        repo_type += " archived"
    if repository.raw_data["is_template"]:
        repo_type += " (template)"

    return repo_type


def extract_repository_data(repository: Repository, repo_data, branch_data):
    repo_type = get_repo_type(repository)
    print(LOG_VALUES.format(repository.full_name, repo_type))

    if repository.private:
        contrib_count = 0
        contributers, days_between_last_commit_creation = "", ""

        last_commit_date = get_last_commit_date(repository)
        if last_commit_date:
            days_between_last_commit_creation = (last_commit_date - repository.created_at).days

            # last commit date can be earlier than repository creation date for mirrored repositories
            if last_commit_date >= repository.created_at:
                contrib_count, contributers = get_contributers(repository)
                if contrib_count == 0:
                    # ignore commits from the mirrored repository
                    contrib_count, contributers = get_commit_authors_since_created(repository)

        administrators = get_administrators(repository)
        if len(administrators) == 0 and contrib_count <= 2:
            creator = contributers
        else:
            creator = administrators

        # Reduce number of api calls due to rate limiting
        topics, branches_count, protections = "", "", ""
        sonar_cloud, workflows, workflow_run = "", "", ""
        if not repository.archived:
            topics = ",".join(repository.get_topics())

            branches = repository.get_branches()
            branches_count = branches.totalCount
            for branch in branches:
                is_default = repository.default_branch == branch.name
                branch_data.append([repository.name, branch.name, is_default, branch.commit.commit.committer.date, branch.commit.commit.committer.name])

            protections = get_default_branch_protections(repository)
            sonar_cloud = contains_string(protections, "sonarcloud")

            workflows = get_workflows(repository)
            workflow_run = contains_string(workflows, gh_config.workflow_name)

        dependabot = repository.get_vulnerability_alert()
        merge_button = get_merge_button_rules(repository)

        repo_data.append([repository.name, repo_type, topics, sonar_cloud, workflow_run, dependabot, repository.created_at, last_commit_date, days_between_last_commit_creation,
                          creator, workflows, branches_count, repository.default_branch, merge_button, repository.delete_branch_on_merge, protections, contrib_count, contributers])


def main():
    csv_repo_rows = []
    csv_branch_rows = []

    gh = Github(gh_config.access_token)
    for repo in gh.get_organization(gh_config.owner).get_repos():
        extract_repository_data(repo, csv_repo_rows, csv_branch_rows)

    create_csv(csv_repo_rows, Columns.REPOS)
    create_csv(csv_branch_rows, Columns.BRANCHES)


if __name__ == "__main__":
    main()