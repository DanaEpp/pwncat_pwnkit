# pwncat_pwnkit

## Introduction
The purpose of this module is to attempt to exploit CVE-2021-4034 (pwnkit) on a target when using pwncat.

There is no need to setup any directories, compile any source or even have gcc on the remote target; the pwnkit module takes care of this automatically using the pwncat framework.

## Setup and Use
- Simply copy `pwnkit.py` somewhere on your host where pwncat-cs is installed. ie: /home/user/pwncat_mods
- In pwncat, simply type: `load /home/user/pwncat_mods`
- To confirm the module loaded, type: `search pwnkit`. You should see something like this:
```
(local) pwncat$ search pwnkit
                                                      Results                                                      
                   ╷                                                                                               
  Name             │ Description                                                                                   
 ══════════════════╪══════════════════════════════════════════════════════════════════════════════════════════════ 
  pwnkit           │ Exploit CVE-2021-4034 to privesc to root
``` 
- To execute, simply type `run pwnkit`. If it's successful, you should see the UID change to 0, and now be root. ie:
```
(local) pwncat$ run pwnkit
[00:12:15] 10.10.184.131:47148: ran pwnkit. UID : Before(1000) | After(0)                            manager.py:955
           Module pwnkit completed successfully                                                          run.py:100
(local) pwncat$                                                                                                    
(remote) root@pwnkit:/# id
uid=0(root) gid=0(root) groups=0(root),1000(tryhackme)
```

## Tips
- If you don't want to always call `load`, you can have pwncat automatically load this module on startup by placing it in `~/.local/share/pwncat/modules`
- To use the cross-compiler to build the exploit on your machine and upload it to the target, you need to set the **cross** variable in your pwncatrc file. This file is typically found at ~/.local/share/pwncat/pwncatrc`. ie:
```
# Set the gcc path
set cross "/usr/bin/gcc"
```

## Thanks
A special shout out to [Caleb Stewart](https://github.com/calebstewart/pwncat) for being helpful as I pushed through learning the pwncat framework from a dev perspective. I will get a pull request to put this in the main pwncat escalate module someday when I have free time... I promise. :-) 
