# openbaopy
OpenBao Client library to authenticate and perform several OpenBao api actions.

# Install
```
pip install git+https://github.com/PortalMario/openbaopy.git
```

# Basic Usage
If the socket path is set during object instantiation, a preinstalled, authenticated openbao-agent unix socket is being used. You are going to need a suitable openbao approle role_id and secret_id for non unix socket auth.

### Approle Auth
```python
from openbaopy.bao import Bao

bao_ip_address = "127.0.0.1"
bao_role_id = "xxxxxxxx"
bao_secret_id = "xxxxxxxx"

try:
    bao_client = Bao(bao_ip=bao_ip_address, verify=False, role_id=bao_role_id, secret_id=bao_secret_id)
except Exception as ex:
    print(f'Could not connect to openbao: { bao_ip_address } - { ex }')
    sys.exit(1)
```

### Unix Socket Auth
```python
from openbaopy.bao import Bao

bao_socket_path = "/etc/bao/bao-agent.sock"

try:
    bao_client = Bao(verify=False, socket_path=bao_socket_path)
except Exception as ex:
    print(f'Could not connect to openbao: { bao_socket_path } - { ex }')
    sys.exit(1)
```

# Usage
**The library is well documented. Use type hints and docstrings for documentation.**

## Example: generate_certificate
```python
server_fqdn = "mycool.server.com"

try:
    response = bao_client.generate_certificate(common_name=server_fqdn, pki="mycool-ca", pki_role="mycool-ca-role")
    print(response)
except Exception as ex:
    print(f'Could not genereate cert: {ex}')
    sys.exit(1)
```
