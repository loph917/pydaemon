"""Generic linux daemon base class for python 3.x."""

import sys, os, time, atexit, signal

class daemon:
    """A generic daemon class.

    Usage: subclass the daemon class and override the run() method."""

    def __init__(self, progname, pidfile):
        self.progname = progname
        self.pidfile = pidfile
        
        # setup the signals
        signal.signal(signal.SIGUSR1, self.receive_signal)
        signal.signal(signal.SIGUSR2, self.receive_signal)
        signal.signal(signal.SIGHUP, self.receive_signal)
        signal.signal(signal.SIGTERM, self.receive_signal)
    
    def daemonize(self):
        """Deamonize class. UNIX double fork mechanism."""
        
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit first parent
                sys.exit(0) 
        except OSError as err: 
            sys.stderr.write('fork #1 failed: {0}\n'.format(err))
            sys.exit(1)
    
        # decouple from parent environment
        os.chdir('/') 
        os.setsid() 
        os.umask(0) 
    
        # do second fork
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit from second parent
                sys.exit(0) 
        except OSError as err: 
            sys.stderr.write('fork #2 failed: {0}\n'.format(err))
            sys.exit(1) 
    
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
    
        # write pidfile
        atexit.register(self.delpid)

        pid = str(os.getpid())
        with open(self.pidfile,'w+') as f:
            f.write(pid + '\n')
        
        return pid
    
    def delpid(self):
        os.remove(self.pidfile)

    def chkpid(self):
        """Checks for the pid file."""
        try:
            with open(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None
            
        return pid

    def start(self, restart = False):
        """Start the daemon."""

        # Check for a pidfile to see if the daemon already runs
        pid = self.chkpid()
    
        if pid:
            message = "pidfile {0} (pid={1}) already exist. " + \
                    "daemon already running?\n"
            sys.stderr.write(message.format(self.pidfile, pid))
            sys.exit(1)
        else:            
            # Start the daemon
            pid = self.daemonize()
            message = 'started daemon pid={}'.format(pid)
            self.log.info(message)
            
            #self.run()
            return pid

    def stop(self):
        """Stop the daemon."""

        # Get the pid from the pidfile
        try:
            with open(self.pidfile,'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None
    
        if not pid:
            message = "pidfile {0} does not exist. " + \
                    "daemon not running?\n"
            sys.stderr.write(message.format(self.pidfile))
            return # not an error in a restart

        message = 'stopping daemon pid={}'.format(pid)
        self.log.info(message)
        
        # Try killing the daemon process    
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            e = str(err.args)
            if e.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print (str(err.args))
                self.log.info('stopped daemon, pid=(%d)' % pid)
                sys.exit(1)

    def restart(self):
        """Restart the daemon."""
        message = 'restarting daemon'
        self.log.info(message)
        
        self.stop()
        pid = self.start(True)
        message = 'restarted daemon pid={}'.format(pid)
        self.log.info(message)

    def status(self):
        """return the status of the damon"""
        pid = daemon.chkpid(self)
        if pid:
            print('%s running (pid=%d)' % (self.progname, pid))
        else:
            print('%s is not runing' % (self.progname))

    def run(self):
        """You should override this method when you subclass Daemon.
        
        It will be called after the process has been daemonized by 
        start() or restart()."""
