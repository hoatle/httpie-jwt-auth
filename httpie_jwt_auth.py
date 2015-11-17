"""
JWTAuth auth plugin for HTTPie.
"""
import os

from httpie.plugins import AuthPlugin

__version__ = '0.2.0-dev0'
__author__ = 'hoatle'
__license__ = 'BSD'


class JWTAuth(object):
    """JWTAuth to set the right Authorization header format of JWT"""

    def __init__(self, token, auth_prefix):
        self.token = token
        self.auth_prefix = auth_prefix

    def __call__(self, request):
        request.headers['Authorization'] = '{} {}'.format(self.auth_prefix, self.token)
        return request


class JWTAuthPlugin(AuthPlugin):
    """Plugin registration"""

    name = 'JWT auth'
    auth_type = 'jwt'
    description = 'Set the right format for JWT auth request'

    @staticmethod
    def after_loaded():
        from httpie import cli
        cli.auth.add_argument(
            '--token',
            help="""
            The jwt token to be used
            """)
        cli.auth.add_argument(
            '--auth-prefix',
            help="""
            The jwt auth prefix for Authorization header, default: Bearer
            """)

    def get_auth(self, username, password):
        token = self.args.token or username
        auth_prefix = 'Bearer'
        if self.args.auth_prefix:
            auth_prefix = self.args.auth_prefix
        elif hasattr(os.environ, 'JWT_AUTH_PREFIX'):
            auth_prefix = os.environ['JWT_AUTH_PREFIX']
        return JWTAuth(token, auth_prefix)
