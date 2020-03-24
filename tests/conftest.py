import pytest
import socket
from unittest.mock import Mock

from agent.iptables_helper import DROP_CHAIN


RASPBERRY_FIXTURE = """
Hardware        : BCM2708
Revision        : 900092
Serial          : 00000000ebd5f1e8
"""

INVALID_CERT = """
-----BEGIN CERTIFICATE-----
MIIC5TCCAc2gAwIBAgIJAPMjGMrzQcI/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0xOTAzMDUyMDE5MjRaFw0xOTA0MDQyMDE5MjRaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAOgfhzltW1Bx/PLve7sk228G9FeBQmTVkEwiU1tgagvIzM8fhoeDnXoMVRf5
GPWZr4h0E4BtDRQUO7NqgW+r3RQMq4nJljTV9f8Om3Owx41BM5M5w5YH75JZzcZ1
OVBmJRPOG06I3Hk/uQjCGo1YN7ZggAdUmFQqQ03GdstqQhd6UzbV2dPphq+R2npV
oAjByawBwuxi+NJXxz20dUVkXrrxGgDUKcUn4NPsIUGf9hSHZcDMZ3XQcQQ/ykD9
i/zeVU6jGnsMOO+YZUguBlq/GKI2fzezfG7fv394oAJP9mV0T8k9ArciTigUehuv
a8sHA+vrvRXCNbpV8vEQbRh/+0sCAwEAAaM6MDgwFAYDVR0RBA0wC4IJbG9jYWxo
b3N0MAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0B
AQsFAAOCAQEAL+KRDdqbbAFiMROy7eNkbMUj3Dp4S24y5QnGjFl4eSFLWu9UhBT+
FcElSbo1vKaW5DJi+XG9snyZfqEuknQlBEDTuBlOEqguGpmzYE/+T0wt9zLTByN8
N44fGr4f9ORj6Y6HJkzdlp+XCDdzHb2+3ienNle6bWlmBpbQaMVrayDxJ5yxldgJ
czUUClEc0OJDMw8PsHyYvrl+jk0JFXgDqBgAutPzSiC+pWL3H/5DO8t/NcccNNlR
2UZyh8r3qmVWo1jROR98z/J59ytNgMfYTmVI+ClUWKF5OWEOneKTf7dvic0Bqiyb
1lti7kgwF5QeRU2eEn3VC2F5JreBMpTkeA==
-----END CERTIFICATE-----
"""


INVALID_KEY = """
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDoH4c5bVtQcfzy
73u7JNtvBvRXgUJk1ZBMIlNbYGoLyMzPH4aHg516DFUX+Rj1ma+IdBOAbQ0UFDuz
aoFvq90UDKuJyZY01fX/DptzsMeNQTOTOcOWB++SWc3GdTlQZiUTzhtOiNx5P7kI
whqNWDe2YIAHVJhUKkNNxnbLakIXelM21dnT6Yavkdp6VaAIwcmsAcLsYvjSV8c9
tHVFZF668RoA1CnFJ+DT7CFBn/YUh2XAzGd10HEEP8pA/Yv83lVOoxp7DDjvmGVI
LgZavxiiNn83s3xu379/eKACT/ZldE/JPQK3Ik4oFHobr2vLBwPr670VwjW6VfLx
EG0Yf/tLAgMBAAECggEBALPEbxJfid+UV+TA6Z823SZwSV1XgtbauqTr1Iio85fq
zAsAjEx49sWltWUaimTywAm6c7v7OKy7Or0pl9KnVFEJuvO8BjMnHRuJ8YQ4fWL9
AvdbPgj8XmKGYCH5eQi2ArMC5Qz+W1kfq6qHwM6Eaqk4tQ54SnysOnGKaUgCI+tP
XBIuWTs6OrWmJDuW6J0zNPRBZAbVEsaFaTdLtJ4kDPlmDmHHMzrLkQhvQ7oSFoEW
FtLNlWAV0uZ2PpHQbrcx1ALabH1Yz3yRcgjDYtu5oCRN6+4wJEylg1NxiQk9BP/m
amRFIuyBVpnh69ErYeLrP320nHew3NML6Xxr3dI9yVECgYEA/3oAR6rCVtjrozHG
hWq/SdRY5Cq4nvt+ocTlgZo2/qULDR8xo4HE4ABliE9/TMEysgA2erAfEvSV15mt
m/BWOHZZ1mbpAm1jbRmBMjVPGytH997LOAnBCwLLjtIjbJMrRxKws6fSO+gwRY9v
MMeiJdW2LpVgBd+AunZEBjyMYCMCgYEA6JlHM5SyCfwuZSdIue0iI3t8n8nBV7zu
mqwItZHX/h8xu/V5cT7eVLsC3yti2+EHir8V6AXJ919LlSFjZObEBwL+xtyK+HZj
uQmXN78QtnFRUO3EBlTmYCYzPGE0cNwg9t1RQS0KMs5ypQ9vYUoXwqNvp97XxsB0
d4+wMLz+lrkCgYEA1ibWhTzGmzZKkAnxd3T71E+EE/8bs2jtxXzfRbyXzO1cTiuP
2Je3CG5Mre61rwlkDYHQKRfpdGJCGPBhbw4PuFS9CdRKDhbT+WgfvI6jOQsW0NiZ
UOgcQbaeG6Jav3C+Hl20cWSD/mOr0yNg+WreqQh0JqhgTYwExEjOzMuEgDECgYBD
niugxx1q4bDrHxx5UIKYJhH4scJPK1GCDXkKr7dG3PKsXZRMY6Zmo2cWUZqPqT90
ClDn/qbUDxP96pLmhl9+WlSOoxaTXHdpF2yqfBTztMWa7UQLQysl0HUcnHWOSbAb
lANHGzzXwER7z5zlf5CguLqA5rt7v/8bst3ZjVfFoQKBgQCFepRalYYqKUYbl6Lx
y0UxgC/XRPUlsL5IANipOt8Yu2M/+RJKW1jdUJx3sUCRYBV5IpX8jqnHax+MIki5
wU3JBrpGqAAoGa/78B572+9Dmr6Bj0yAoWQ67tht87M1mQxpKv6IE4CEt8+o+5sR
I9bBs17EE1GV43TaxFaOc/oUYw==
-----END PRIVATE KEY-----
"""


CERT = """
-----BEGIN CERTIFICATE-----
MIIClzCCAj2gAwIBAgIUFXu9cEa7n79yDQWNHG9nfHHiw+kwCgYIKoZIzj0EAwIw
XzELMAkGA1UEBhMCVUsxDzANBgNVBAcTBkxvbmRvbjEjMCEGA1UEChMaV2ViIG9m
IFRydXN0ZWQgVGhpbmdzLCBMdGQxGjAYBgNVBAMTEWNhMC1jYS53b3R0LmxvY2Fs
MB4XDTE5MDMxMjEwMjQwMFoXDTE5MDMxOTEwMjQwMFowezELMAkGA1UEBhMCVUsx
DzANBgNVBAgTBkxvbmRvbjEjMCEGA1UEChMaV2ViIG9mIFRydXN0ZWQgVGhpbmdz
LCBMdGQxNjA0BgNVBAMTLTQ4NTNiNjMwODIyOTQ2MDE5MzkzYjE2YzViNzEwYjll
LmQud290dC5sb2NhbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEzKyyQJ2VSw
5F90xOkHLaJmTHjJwu3C/G2fgYDMw02NbuTzjIhTCyqhHbeY8GO/ZXIZ5ASE1ACB
4OJVYrpRUVajgbowgbcwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUF
BwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSshZgvlzrA9p6p
EJXTRi4wgYOyITAfBgNVHSMEGDAWgBSpts1xq4g96OM2x5RvKrEUAIU3ATA4BgNV
HREEMTAvgi00ODUzYjYzMDgyMjk0NjAxOTM5M2IxNmM1YjcxMGI5ZS5kLndvdHQu
bG9jYWwwCgYIKoZIzj0EAwIDSAAwRQIgGSUuYz+Osx1FFZnIntWlb2g3dkpT1O/C
5zSuz7b/JcECIQDTa1z7edWWjwBLmFwaCR/2XXU6pt/52Fh+YUq/vwGq5A==
-----END CERTIFICATE-----
"""


KEY = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGJEzRpQVxxo0jRKh
0zV00O5iyOkUajHp9ULu0vE6J3KhRANCAARMysskCdlUsORfdMTpBy2iZkx4ycLt
wvxtn4GAzMNNjW7k84yIUwsqoR23mPBjv2VyGeQEhNQAgeDiVWK6UVFW
-----END PRIVATE KEY-----
"""


@pytest.fixture
def raspberry_cpuinfo():
    return RASPBERRY_FIXTURE


@pytest.fixture
def netif_gateways():
    return {
        'default': {
            2: ('192.168.1.1', 'wlo1')
        },
        2: [('192.168.1.1', 'wlo1', True)]
    }


@pytest.fixture
def netif_ifaddresses():
    return {
        17: [
            {
                'addr': 'aa:aa:aa:aa:aa:aa',
                'broadcast': 'ff:ff:ff:ff:ff:ff'
            }
        ],
        2: [
            {
                'addr': '192.168.1.3',
                'netmask': '255.255.255.0',
                'broadcast': '192.168.1.255'
            }
        ],
        10: [
            {
                'addr': 'fe80::1e93:cce9:0000:0000%wlo1',
                'netmask': 'ffff:ffff:ffff:ffff::/64'
            }
        ]
    }


@pytest.fixture
def netif_gateways_invalid():
    return {}


@pytest.fixture
def cert():
    return CERT


@pytest.fixture
def key():
    return KEY


@pytest.fixture
def invalid_cert():
    return INVALID_CERT


@pytest.fixture
def invalid_key():
    return INVALID_KEY


@pytest.fixture
def gen_id():
    return {"device_id": "60f4e66c1e7746c3ba8f3301d8a4d1c4.d.wott.local"}


@pytest.fixture
def uptime():
    return "60 60"


@pytest.fixture
def ipt_rules():
    return (
        {'dst': '10.10.10.10', 'target': DROP_CHAIN},
        {'dst': '10.20.10.20', 'target': DROP_CHAIN}
    )


@pytest.fixture
def ipt_networks():
    return (('10.10.10.10', False), ('10.20.10.20', False))


@pytest.fixture
def ipt_ports():
    return [
        ('0.0.0.0', 'tcp', 80, False),
        ('::', 'tcp', 80, True),
        ('192.168.1.1', 'tcp', 80, False),
        ('fe80::adf3:7685:af9f:c151', 'tcp', 80, True)
    ]


@pytest.fixture
def ipt_ports_rules():
    return [
        ({'protocol': 'tcp', 'tcp': {'dport': '80'}, 'target': DROP_CHAIN}, False),
        ({'protocol': 'tcp', 'tcp': {'dport': '80'}, 'dst': '192.168.1.1', 'target': DROP_CHAIN}, False),
    ]


@pytest.fixture
def net_connections_fixture():
    return [
        Mock(family=socket.AF_INET,
             type=socket.SOCK_STREAM,
             laddr=('192.168.1.1', 1234),
             raddr=('192.168.1.2', 1234),
             status='CONNECTED',
             pid=1234),
        Mock(family=socket.AF_INET,
             type=socket.SOCK_STREAM,
             laddr=('192.168.1.1', 1234),
             raddr=(),
             status='LISTENING',
             pid=1234)
    ]


@pytest.fixture
def netstat_result():
    return (
        {
            'ip_version': 4,
            'type': 'tcp',
            'local_address': ('192.168.1.1', 1234),
            'remote_address': ('192.168.1.2', 1234),
            'status': 'CONNECTED',
            'pid': 1234
        },
        {
            'ip_version': 4,
            'host': '192.168.1.1',
            'port': 1234,
            'proto': 'tcp',
            'state': 'LISTENING',
            'pid': 1234
        }
    )


@pytest.fixture
def sshd_config():
    return """
# a comment
PermitEmptyPasswords no
PermitRootLogin   "yes"

# Ignored with OpenSSH >= 7.0
Protocol  "2,1"

# PasswordAuthentication param's default value will be checked
LoginGraceTime 60

# outside of range
MaxAuthTries 5

# inside the range
ClientAliveCountMax 1

# default: ClientAliveInterval 0

AnotherOption another value
"""


@pytest.fixture
def cmdline():
    return """one t-wo= fo_ur="fix 1-2asqwe six+\\0123!@#$%^%^&*()_=" se.ven=eight,nine+ten*eleven -"""
