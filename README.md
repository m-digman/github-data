# github-data
Audit repository and security vulnerability data using GitHub Rest and GraphQL API's

## Dependencies
- Python 3.10
- See requirements.txt (use: pip install -r requirements.txt)

# Configuration Setup
The settings needed to extract data from GitHub is stored in github_conf.yaml

To stop any changes to this file getting back into Git use:
```
# use --no-skip-worktree to undo
git update-index --skip-worktree github_config.yaml
```
## github_config.yaml
Edit github_config.yaml and set the token, owner, repositories and workflow. These are the values specific to your organizations GitHub account, example:
```yaml
- github:
    token: ghp_token
    owner: my-org
    repositories: some-repo, other-repo
    workflow: GitHub Workflow Name
```
### Token
Create a GitHub Personal Access Token against your GitHub account with the "repo" scope and store it somewhere safe:
- https://docs.github.com/en/rest/guides/getting-started-with-the-rest-api
- https://github.com/settings/tokens
### Owner
Identifies the owner of the repositories that you want to extract data on, this could be a personal profile or organization
### Repositories
List of repositories that you want to extract security vulnerability data for. These must have the same owner defined in the config above. Used in audit.py only.
### Workflow
You can choose to see if each repository reported on by extract.py has a specific GitHub workflow configured. This is the name of any GitHub workflow yml file found in ".github/workflows". Used in extract.py only.  

# Scripts
## extract.py
Extracts information about all repositories for the owner specified in github_config.yaml via the GitHub Rest API. This script generates a .CSV file with the following columns:
- Name
- Type
- Topics
- SonarCloud (branch protection)
- Workflow (is configured)
- Dependabot (alerts configured)
- Created (date)
- Last Commit (date)
- Diff (days)
- Admin/Creator
- Workflows (configured)
- Branches
- Default (branch)
- Merge Button (allowed rules)
- Auto Delete Branch
- Protections (branch)
- No. Contributers
- Contributers
### Usage
```python
py extract.py
```

## audit.py
Extracts security vulnerabilities identified by GitHub Dependabot via the GitHub GraphQL API. To get this data for a repository the "Dependency graph" and "Dependabot alerts" security and analysis features need to be enabled. This script generates a .CSV file with the following columns:
- Repository
- Dependency
- From (manifest)
- Status
- Severity
- CVSS (score)
- Summary
- Upgrade (type: Major, Minor, Patch)
- Diff (in version)
- Affected Versions
- Patched Version
- Current Version
- Published (date)
- Link
- Dismisser
- Reason
- Closed (date)
### Usage
```python
py audit.py
```