import yaml

class github_config(object):
    __github_config_file = "github_config.yaml"


    def __init__(self, config_file = None):
        if config_file:
            self.__github_config_file = config_file
        self.__load_config()


    def __load_config(self):
        with open(self.__github_config_file, "r") as config_file:
            config = yaml.safe_load(config_file)
            self.__access_token = config[0]["github"]["token"]
            self.__owner = config[0]["github"]["owner"]
            self.__repositories = config[0]["github"]["repositories"].replace(" ", "").split(",")
            self.__workflow_name = config[0]["github"]["workflow"]


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