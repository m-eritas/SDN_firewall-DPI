from ryu.cmd.manager import main as ryu_main
from multiprocessing import Process, Event
import sys, os

def firewall_main():
    """
        main.py  –  Entry point for the SDN Firewall
        Internally starts ryu-manager forwarding to it all cli arguments
    """
    app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'firewall_app.py')
    sys.argv = ['ryu-manager', app_path] + sys.argv[1:]                                                                 # Rewrite argv so ryu's manager sees:  ryu-manager firewall_app.py [flags]
    ryu_main()                                                                                                          # Invoke ryu-manager from this code -> use ryu_main() function with normal cli command as argv


if __name__ == '__main__':
    stop_event = Event()                                                                                                # multiprocess shared flag (like sem_t but in python, lol)

    firewall_process = Process(target=firewall_main)
    firewall_process.start()
    # mininet process here was creating import issues (colliding and too-old versions)
    try:
        firewall_process.join()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()                                                                                                # signal mininet to stop (and internally call cleanup)
