import yaml

class github_config(object):
    __github_config_file = "github_config.yaml"
    __workflow_name = ""


    def __init__(self, config_file = None):
        if config_file:
            self.__github_config_file = config_file
        self.__load_config()


    def __load_config(self):
        with open(self.__github_config_file, "r") as config_file:
            config = yaml.safe_load(config_file)
            github_values = config[0]["github"]
            self.__access_token = github_values["token"]
            self.__owner = github_values["owner"]
            self.__repositories = github_values["repositories"].replace(" ", "").split(",")
            if len (github_values) > 3:
                self.__workflow_name = github_values["workflow"]


    @property
    def access_token(self):
        return self.__access_token


    @property
    def owner(self):
        return self.__owner


    @property
    def repositories(self):
        return self.__repositories


    @property
    def workflow_name(self):
        return self.__workflow_name