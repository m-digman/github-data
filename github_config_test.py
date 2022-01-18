import unittest
from github_config import github_config


class github_config_test(unittest.TestCase):


    def setUp(self):
        self.config = github_config("test_config.yaml")


    def test_token_returned(self):
        actual = self.config.access_token
        self.assertEqual(actual, "ghp_T0k3n")


    def test_owner_returned(self):
        actual = self.config.owner
        self.assertEqual(actual, "someorg")


    def test_repositories_returned(self):
        actual = self.config.repositories
        self.assertEqual(actual[0], "my-repo")
        self.assertEqual(actual[1], "another-repo")


    def test_workflow_name_returned(self):
        actual = self.config.workflow_name
        self.assertEqual(actual, "My GitHub Workflow")


if __name__ == '__main__':
    unittest.main()