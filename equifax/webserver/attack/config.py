from dataclasses import dataclass

@dataclass
class Target:
    webserver_url: str = "http://localhost:8080"
    database_ssh_alias: str = "database"
    loot_path: str = "/home/database/data.json"
