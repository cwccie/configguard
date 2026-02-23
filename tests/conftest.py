"""Shared test fixtures."""

import pytest
from pathlib import Path

SAMPLE_CISCO_CONFIG = """!
hostname TEST-RTR-01
!
enable password cisco123
no service password-encryption
service finger
service pad
!
username admin password 0 admin123
!
interface GigabitEthernet0/0
 ip address 10.1.1.1 255.255.255.0
 no shutdown
!
snmp-server community public RO
snmp-server community private RW
!
logging buffered 4096
!
line con 0
 password console123
 login
!
line vty 0 4
 password vtypass
 transport input telnet ssh
!
end
"""

SAMPLE_COMPLIANT_CONFIG = """!
hostname COMPLIANT-RTR-01
!
service password-encryption
service timestamps log datetime msec localtime show-timezone
service timestamps debug datetime msec localtime show-timezone
service tcp-keepalives-in
service tcp-keepalives-out
no service finger
no service pad
!
no ip source-route
no ip http server
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
enable algorithm-type scrypt secret 9 $14$abc...
!
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
aaa accounting commands 15 default start-stop group tacacs+
!
login block-for 120 attempts 3 within 60
!
username admin privilege 15 algorithm-type scrypt secret 9 $14$xyz...
!
interface GigabitEthernet0/0
 ip address 10.1.1.1 255.255.255.0
 ip access-group FILTER in
 no shutdown
!
access-list 100 permit tcp any host 10.1.1.1 eq 22
access-list 100 deny ip any any log
!
snmp-server group SNMPV3GRP v3 priv
snmp-server user snmpuser SNMPV3GRP v3 auth sha AuthPass priv aes 256 PrivPass
!
ntp authenticate
ntp authentication-key 1 md5 ntpkey123
ntp trusted-key 1
ntp server 10.0.0.50 key 1
!
logging host 10.0.0.100
logging trap informational
logging console critical
logging buffered 64000 informational
!
banner login #
Authorized access only. All activity is monitored.
#
!
line con 0
 exec-timeout 5 0
 login authentication default
!
line vty 0 15
 exec-timeout 5 0
 access-class MGMT-ACCESS in
 transport input ssh
 session-limit 2
 login authentication default
!
end
"""

SAMPLE_JUNOS_CONFIG = """
set system host-name JUNOS-TEST-01
set system services ssh protocol-version v2
set system services telnet
set system syslog host 10.0.0.100 any info
set interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/24
set snmp community public authorization read-only
"""

SAMPLE_PALOALTO_CONFIG = """
set deviceconfig system hostname PA-TEST-01
set network interface ethernet ethernet1/1 layer3 ip 10.1.1.1/30
set rulebase security rules allow-all from any to any action allow
set deviceconfig setting management http
"""


@pytest.fixture
def cisco_config():
    return SAMPLE_CISCO_CONFIG


@pytest.fixture
def compliant_config():
    return SAMPLE_COMPLIANT_CONFIG


@pytest.fixture
def junos_config():
    return SAMPLE_JUNOS_CONFIG


@pytest.fixture
def paloalto_config():
    return SAMPLE_PALOALTO_CONFIG


@pytest.fixture
def sample_configs_dir():
    return Path(__file__).parent.parent / "sample_configs"


@pytest.fixture
def rules_dir():
    return Path(__file__).parent.parent / "rules"
