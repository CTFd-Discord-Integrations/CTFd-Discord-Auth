import requests
import logging


class Discord_Oauth(object):

    """
    Class to handle the Discord OAuth2 process and get
    """

    client_id = ""
    client_secret = ""
    scope = ""
    redirect_uri = ""
    discord_oauth_url = ""

    def __init__(self, client_id: str, client_secret: str, scope: list, redirect_uri: str,
                 discord_api_url: str, plugin_name: str):
        """
        Initialization for Discord_Oauth class, sets class variables and logger.

        :return: Discord_Oauth instance
        """
        # Class Obj registration
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = "%20".join(str(perm) for perm in scope)
        self.redirect_uri = redirect_uri
        self.discord_api_url = discord_api_url
        self.discord_oauth_url = f"{discord_api_url}/oauth2"
        # Log registration
        self.log = logging.getLogger(f"{plugin_name}:{self.__class__.__name__}")

    def get_access_token(self, code):
        """
        Retreive the user's access token from their code

        :code: Access code retrieved from discord from initial handoff
        :return: User access token to perform queries
        """
        self.log.debug("code 32: [{}]".format(code))
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope
        }
        self.log.debug("payload: [{}]".format(str(payload)))
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        # JSON access token response
        access_token = requests.post(
            url=f"{self.discord_oauth_url}/token",
            data=payload,
            headers=headers
        )
        self.log.debug("access_token: {}".format(str(access_token)))
        json_data = access_token.json()
        return json_data.get("access_token")

    def get_user_info(self, access_token):
        """
        Get user's Discord information from API endpoint

        :access_token: Authorization token for the user
        :return: JSON object of a users information.
        """
        url = f"{self.discord_api_url}/users/@me"
        self.log.debug("url: [{}]".format(url))
        self.log.debug("access_token: [{}]".format(access_token))
        headers = {
            "Authorization": "Bearer {}".format(access_token)
        }
        user_obj = requests.get(url=url, headers=headers)
        return user_obj.json()

    def gen_auth_url(self):
        """
        Generates the authorization url used to link to Discord's OAuth2 API

        :return: Generated URL to redirect to
        """
        return (
            f"{self.discord_oauth_url}/authorize?"
            f"client_id={self.client_id}&redirect_uri={self.redirect_uri}&"
            f"response_type=code&scope={self.scope}"
        )
