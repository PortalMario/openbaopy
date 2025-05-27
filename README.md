# openbaopy
OpenBao Client library to authenticate and perform several OpenBao api actions. (Linted with flake8 and pylint)

[![project-linting](https://github.com/PortalMario/openbaopy/actions/workflows/linting.yml/badge.svg)](https://github.com/PortalMario/openbaopy/actions/workflows/linting.yml)

# Install
```
pip install git+https://github.com/PortalMario/openbaopy.git@v1.0.0
```

# Basic Usage
If the socket path is set during object instantiation, a preinstalled, authenticated openbao-agent unix socket is being used. You are going to need a suitable openbao approle role_id and secret_id for non unix socket auth.

### Approle Auth
```python
import sys
from openbaopy.bao import Bao, BaoAuthParams

auth_params = BaoAuthParams(
    bao_address="127.0.0.1",
    verify=True,
    role_id='xxxxx-xxxx-xxxx-xxx',
    secret_id='xxxxx-xxxx-xxxx-xxx'
)

try:
    bao_client = Bao(auth_params=auth_params)
except Exception as ex:
    print(f'Could not connect to openbao: { auth_params.bao_address } - { ex }')
    sys.exit(1)
```

### Unix Socket Auth
```python
import sys
from openbaopy.bao import Bao, BaoAuthParams

auth_params = BaoAuthParams(
    socket_path="/etc/bao/bao-agent.sock",
    verify=False
)

try:
    bao_client = Bao(auth_params=auth_params)
except Exception as ex:
    print(f'Could not connect to openbao: { ex }')
    sys.exit(1)
```

# Usage
**The library is well documented. Use type hints and docstrings for documentation.**

## Example: generate_certificate
```python
server_fqdn = "mycool.server.com"

try:
    response = bao_client.generate_certificate(
        common_name=server_fqdn,
        pki="mycool-ca",
        ttl="72h",
        pki_role="mycool-ca-role"
        )

    print(response)
except Exception as ex:
    print(f'Could not genereate cert: {ex}')
    sys.exit(1)
```
