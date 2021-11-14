import subprocess
import sys

gadget = sys.argv[1]

dll_prefix = "./DLLs/"
dll_names = ["msvcr71.dll"]
dll_paths = [dll_prefix + dll_name for dll_name in dll_names]
dll_path = "./DLLs/msvcr71.dll"

status, output = subprocess.getstatusoutput(f"sky_search_raw --all -i \"{gadget}\" {dll_path}")
addresses = [line.split()[0] for line in output.splitlines()[3:]]

for address in addresses:
    status2, output2 = subprocess.getstatusoutput(f"msfpescan -a {address} -D {dll_path}")
    ls = [l.split('\t') for l in output2.splitlines()[3:5]]
    if len(ls) >=2 and ls[1][1] == "ret":
        print(f"{dll_path} -- {address}: {gadget}; ret;")