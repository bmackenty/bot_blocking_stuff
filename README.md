# Bot blockers
These scripts are used to block bots and word-press attacks using apache2 analysis and UFW
They are all hacky and specific to linux / apache2 environment. 

wp_block.py can be executed by running sudo python3 wp_block.py This script also has a dry run mode, which can be executed by running:  sudo python3 wp_block.py --dry-run

block.py is simply executed by running: sudo python3 block.py

These two scripts added about 4000 blocked IP's to my UFW (IPtables) DENY rules. I have heard that systems can become slower with thousands of rules, but I haven't seen it yet. Needless to say, I advise careful monitoring of system resources. Apparently there are much faster firewalls for linux. 

