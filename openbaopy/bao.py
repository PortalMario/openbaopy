"""
OpenBao Client library to authenticate and perform several OpenBao api actions.
"""
import os
import urllib.parse
from dataclasses import dataclass
import urllib3
import requests_unixsocket
from hvac import Client
import hvac.exceptions
from openbaopy import exceptions


@dataclass
class BaoAuthParams:
    """
    Attributes:
        bao_address (str): IPv4 Address or FQDN of OpenBao Server.
        self.__auth_params.verify (bool): Whether TLS Verification
            should be ignored.
        role_id (str): OpenBao approle role_id for authentification.
        secret_id (str): OpenBao approle secret_id for authentification.
        self.__auth_params.socket_path (str): Filesystem Path to
            openbao agent unix socket. If set, approle value will be ignored.
    """
    bao_address: str | None = None
    verify: bool = True
    role_id: str | None = None
    secret_id: str | None = None
    socket_path: str | None = None


class Bao:
    """
    OpenBao Client.
    """
    def __init__(self, auth_params: BaoAuthParams):
        """
        Initialize a new OpenBao client instance.

        Args:
            auth_params (BaoAuthParams): Params needed for openbao server auth.

        Raises:
            FileNotFoundError: Socket path does not exist.
            PermissionError: Socket path is not writable.
            hvac.exceptions.Unauthorized: OpenBao server authentication error.
        """

        self.__auth_params: BaoAuthParams = auth_params

        # Disable insecure tls warnings
        if self.__auth_params.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Use socket
        if self.__auth_params.socket_path:
            if not os.path.exists(self.__auth_params.socket_path):
                raise FileNotFoundError('Socket path does not exist: ' +
                                        self.__auth_params.socket_path)

            if not os.access(self.__auth_params.socket_path, os.W_OK):
                raise PermissionError('Socket path is not writable: ' +
                                      self.__auth_params.socket_path)

            encoded_path = urllib.parse.quote(
                self.__auth_params.socket_path,
                safe=''
                )
            socket_url: str = f'http+unix://{encoded_path}'

            socket_session = requests_unixsocket.Session()
            self.__bao_client: Client = Client(
                url=socket_url,
                session=socket_session,
                verify=self.__auth_params.verify
            )

        # Use approle directly
        else:
            bao_address: str = self.__auth_params.bao_address
            role_id: str = self.__auth_params.role_id
            secret_id: str = self.__auth_params.secret_id

            self.__bao_client: Client = Client(
                url=f'https://{bao_address}:8200',
                verify=self.__auth_params.verify
            )

            self.__bao_client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id
                )

            # Check for authentification
            if not self.__bao_client.is_authenticated():
                raise hvac.exceptions.Unauthorized('Cloud not authenticate to bao server!')

    def generate_certificate(self, common_name: str, ttl: str, pki: str, pki_role: str) -> dict:
        """
        Generate new signed x509 certificate.

        Args:
            common_name (str): The Certificates desired Common Name.
            ttl (str): The certificates desired expiration e.g: 72h.
            pki (str): The CA/PKI mount to issue new certificates.
            pki_role (str): The desired openbao pki role.

        Returns:
            dict: Generated Cert, Key, Serial and CA-Chain

        Raises:
            exceptions.UnexpectedError: Error during certificate generation.
        """
        try:
            response = self.__bao_client.secrets.pki.generate_certificate(
                name=pki_role,
                common_name=common_name,
                ttl=ttl,
                mount_point=pki
            )
            return response['data']
        except Exception as ex:
            raise exceptions.UnexpectedError(
                f'Could not generate new cert for: {common_name} - {ex}'
                ) from ex

    def revoke_certificate(self, serial_number: str, pki: str) -> dict:
        """
        Revoke a certificate.

        Args:
            serial_number (str): Serial number of the certificate which
                should be revoked.
            pki (str): The CA/PKI mount which issued the certificate.

        Returns:
            dict: Information of the revocation.

        Raises:
            ValueError: If serial_number is empty.
            ValueError: If serial_number contains wildcards.
            exceptions.UnexpectedError: Error during certificate revocation.
        """
        if not serial_number or len(serial_number) < 1:
            raise ValueError('serial_number is empty')

        if '*' in serial_number:
            raise ValueError(f'Wildcard found in serial_number: {serial_number}')

        try:
            response = self.__bao_client.secrets.pki.revoke_certificate(
                serial_number=serial_number,
                mount_point=pki
            )
            return response['data']
        except Exception as ex:
            raise exceptions.UnexpectedError(f'Could not revoke certificate: {ex}') from ex

    def get_secret(self, path: str, key: str, secrets_mount: str = 'secret') -> str:
        """
        Retrieve secret value.

        Args:
            path (str): OpenBao API path for the secret.
            key (str): Desired key of the secret.
            secrets_mount (str): Mount point for API path.

        Returns:
            str: Value to the secret's key.

        Raises:
            exceptions.UnexpectedError: Error during secret retrieval.
        """
        try:
            response = self.__bao_client.secrets.kv.v1.read_secret(
                path=path,
                mount_point=secrets_mount
            )
            return response['data']['data'][key]
        except Exception as ex:
            raise exceptions.UnexpectedError(
                f'Could not retrieve secret value for: {key} - {ex}'
                ) from ex
