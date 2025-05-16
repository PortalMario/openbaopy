import urllib3
import urllib.parse
import os
import requests_unixsocket
from hvac import Client

class Bao:
    """
    OpenBao Client.

    Attributes:
        bao_address (str): IPv4 Address or FQDN of OpenBao Server.
        verify (bool): Whether TLS Verification should be ignored.
        role_id (str): OpenBao approle role_id for authentification.
        secret_id (str): OpenBao approle secret_id for authentification.
        socket_path (str): Filesystem Path to openbao agent unix socket. If set, approle value will be ignored.
    """
    def __init__(self, bao_address: str | None = None, verify: bool = True, role_id: str | None = None, secret_id: str | None = None, socket_path: str | None = None):
        """
        Initialize a new OpenBao client instance.

        Args:
            bao_address (str): IPv4 Address or FQDN of OpenBao Server.
            verify (bool): Whether TLS Verification should be ignored.
            role_id (str): OpenBao approle role_id for authentification.
            secret_id (str): OpenBao approle secret_id for authentification.
            socket_path (str): Filesystem Path to openbao agent unix socket. If set, approle value will be ignored.

        Raises:
            Exception: OpenBao server authentication error.
        """
        # Disable insecure tls warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Use socket
        if socket_path:
            if not os.path.exists(socket_path) or not os.access(socket_path, os.W_OK):
                raise Exception(f'Socket path does not exist or is not writable: { socket_path }')

            self.__socket_url: str = 'http+unix://{encoded_path}'.format(
                encoded_path=urllib.parse.quote(socket_path, safe='')
                )
            
            self.__socket_session = requests_unixsocket.Session()
            self.__bao_client: Client = Client(
                url=self.__socket_url,
                session=self.__socket_session,
                verify=verify
            )

        # Use approle directly
        else:
            self.__bao_address: str = bao_address
            self.__role_id: str = role_id
            self.__secret_id: str = secret_id

            self.__bao_client: Client = Client(
                url=f'https://{self.__bao_address}:8200',
                verify=verify
            )

            self.__bao_client.auth.approle.login(role_id=self.__role_id, secret_id=self.__secret_id)

            # Check for authentification
            if not self.__bao_client.is_authenticated():
                raise Exception(f'Cloud not authenticate to bao server!')
        

    def generate_certificate(self, common_name: str, pki: str, pki_role: str) -> dict:
        """
        Generate new signed x509 certificate.

        Args:
            common_name (str): The Certificates desired Common Name.
            pki (str): The CA/PKI mount to issue new certificates.
            pki_role (str): The desired openbao pki role.

        Returns:
            dict: Generated Cert, Key, Serial and CA-Chain

        Raises:
            Exception: Error during certificate generation.
        """
        try:
            response = self.__bao_client.secrets.pki.generate_certificate(
                name=pki_role,
                common_name=common_name,
                mount_point=pki
            )
            return response['data']
        except Exception as ex:
            raise Exception(f'Could not generate new cert for: {common_name} - {ex}')
    
    def revoke_certificate(self, serial_number: str, pki: str) -> dict:
        """
        Revoke a certificate.

        Args:
            serial_number (str): Serial number of the certificate which should be revoked.
            pki (str): The CA/PKI mount which issued the certificate.

        Returns:
            dict: Information of the revocation.

        Raises:
            Exception: If serial_number is empty.
            Exception: If serial_number contains wildcards.
            Exception: Error during certificate revocation.
        """
        if not serial_number or len(serial_number) < 0:
            raise Exception('serial_number is empty')
        
        if '*' in serial_number:
            raise Exception(f'Wildcard found in serial_number: { serial_number }')
        
        try:
            response = self.__bao_client.secrets.pki.revoke_certificate(
                serial_number=serial_number,
                mount_point=pki
            )
            return response['data']
        except Exception as ex:
            raise Exception(f'Could not revoke certificate: {ex}')


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
            Exception: Error during secret retrieval.
        """
        try:
            response = self.__bao_client.secrets.kv.v1.read_secret(
                path=path,
                mount_point=secrets_mount
            )
            return response['data']['data'][key]
        except Exception as ex:
            raise Exception(f'Could not retrieve secret value for: {key} - {ex}')