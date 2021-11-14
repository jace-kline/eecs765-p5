import subprocess
import sys

if len(sys.argv) < 3:
    print("Usage: python3 findgadget.py GADGET DLL_PATH")
    exit()

gadget = sys.argv[1]
dll_path = sys.argv[2]

status, output = subprocess.getstatusoutput(f"sky_search_raw --all -i \"{gadget}\" {dll_path}")
addresses = [line.split()[0] for line in output.splitlines()[3:]]

for address in addresses:
    status2, output2 = subprocess.getstatusoutput(f"msfpescan -a {address} -D {dll_path}")
    ls = [l.split('\t') for l in output2.splitlines()[3:5]]
    if len(ls) >=2 and ls[1][1] == "ret":
        print(f"{dll_path} -- {address}: {gadget}; ret;")