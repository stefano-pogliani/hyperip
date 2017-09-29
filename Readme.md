HyperIP
=======
Get a usable Public IP for your Hyperoptic router.


Why
---
The UK ISP [HyperOptic](https://www.hyperoptic.com/) has one of the wierdest
networks I have ever seen and can lead to nightmares (or worse, expenses) if
you are trying to get a Dynamic DNS name working.

Whoever designed their router interface should be forced to use it!
May they pay for that horror (see what the code does to understand this point).

This Python3 script simulates the actions performed by the user to retrive the
Public IP associated to the router.

This is required because:

  * the IP as seen by other services (like googling your public IP)
    is not usable to connect into your device.
  * The DDNS options available in the router itself are payed and/or unkown.

This script (which can also be used as a library) detects the IP address
for you and will let you integrate into other DNS providers for a free/cheap
DDNS experience.

Don't forget to set up your port forwarding though!


Quickstart
----------
```bash
virtualenv --python=python3 hyperip
hyperip/bin/pip install -r requirements.txt
hyperip/bin/python hyperip.py --password MY_PASS 'http://192.168.1.1/'
```

As a library
------------
```python
from hyperip import getStats

stats = getStats('http://192.168.1.1/', 'admin', 'password')
ip = stats['ip']
```
