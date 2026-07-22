#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from enum import Enum


class ConnectionProtocol(Enum):
    RDP = "rdp"
    VNC = "vnc"
    TELNET = "telnet"
    SSH = "ssh"
    KUBERNETES = "kubernetes"
    SQLSERVER = "sql-server"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"
    ORACLE = "oracle"
    MONGODB = "mongodb"
    REDIS = "redis"
    ELASTICSEARCH = "elasticsearch"
    CLICKHOUSE = "clickhouse"
    DYNAMODB = "dynamodb"
    HTTP = "http"
