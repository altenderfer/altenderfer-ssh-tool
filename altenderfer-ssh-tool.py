
import paramiko
import curses
import threading
import logging
import logging.handlers
import queue
import textwrap
import time
import socket

# Get supported algorithms from Paramiko
all_kex_algs = list(paramiko.transport.Transport._preferred_kex)
all_hostkey_algs = list(paramiko.transport.Transport._preferred_keys)
all_ciphers = list(paramiko.transport.Transport._preferred_ciphers)
all_macs = list(paramiko.transport.Transport._preferred_macs)

# Exhaustive lists of algorithms
all_kex_algs = [
    'diffie-hellman-group1-sha1',
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group14-sha256',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group18-sha512',
    'diffie-hellman-group-exchange-sha1',
    'diffie-hellman-group-exchange-sha256',
    'ecdh-sha2-nistp256',
    'ecdh-sha2-nistp384',
    'ecdh-sha2-nistp521',
    'curve25519-sha256',
    'curve25519-sha256@libssh.org',
]
all_hostkey_algs = [
    'ssh-rsa',
    'rsa-sha2-256',
    'rsa-sha2-512',
    'ssh-dss',
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'ssh-ed25519',
]
all_ciphers = [
    'aes128-ctr',
    'aes192-ctr',
    'aes256-ctr',
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
    '3des-cbc',
    'blowfish-cbc',
    'cast128-cbc',
    'arcfour',
    'arcfour128',
    'arcfour256',
    'chacha20-poly1305@openssh.com',
]
all_macs = [
    'hmac-sha1',
    'hmac-sha1-96',
    'hmac-sha2-256',
    'hmac-sha2-512',
    'hmac-md5',
    'hmac-md5-96',
    'umac-64@openssh.com',
    'umac-128@openssh.com',
    'hmac-ripemd160',
    'hmac-ripemd160@openssh.com',
]

def connect(params, log_queue):
    ip = params['ip']
    port = int(params['port'])
    username = params['username']
    password = params['password']
    host_key_algs = params['host_key_algs']
    kex_algs = params['kex_algs']
    ciphers = params['ciphers']
    macs = params['macs']

    logger = logging.getLogger()
    logger.debug("Attempting to connect...")

    # Get supported algorithms from Paramiko
    supported_kex_algs = paramiko.transport.Transport._preferred_kex
    supported_hostkey_algs = paramiko.transport.Transport._preferred_keys
    supported_ciphers = paramiko.transport.Transport._preferred_ciphers
    supported_macs = paramiko.transport.Transport._preferred_macs

    # Intersect selected algorithms with supported ones
    kex_algs = [alg for alg in kex_algs if alg in supported_kex_algs]
    host_key_algs = [alg for alg in host_key_algs if alg in supported_hostkey_algs]
    ciphers = [alg for alg in ciphers if alg in supported_ciphers]
    macs = [alg for alg in macs if alg in supported_macs]

    # Check if any of the algorithm lists are empty
    if not kex_algs:
        logger.error("No supported KEX algorithms selected.")
        return
    if not host_key_algs:
        logger.error("No supported Host Key algorithms selected.")
        return
    if not ciphers:
        logger.error("No supported Ciphers selected.")
        return
    if not macs:
        logger.error("No supported MACs selected.")
        return

    try:
        # Create a socket and connect to the server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, port))

        # Create a Transport object
        transport = paramiko.Transport(sock)
        transport.connect_timeout = 10

        # Set preferred algorithms
        security_options = transport.get_security_options()
        security_options.kex = kex_algs
        security_options.ciphers = ciphers
        security_options.digests = macs  # Changed from 'macs' to 'digests'
        security_options.key_types = host_key_algs  # Use 'key_types'

        # Log the algorithms being proposed
        logger.debug(f"Proposed KEX algorithms: {kex_algs}")
        logger.debug(f"Proposed Host Key algorithms: {host_key_algs}")
        logger.debug(f"Proposed Ciphers: {ciphers}")
        logger.debug(f"Proposed MACs (Digests): {macs}")

        # Start the client
        transport.start_client(timeout=10)

        # Set missing host key policy
        host_key = transport.get_remote_server_key()
        client = paramiko.SSHClient()
        client._transport = transport
        client._host_keys.add(ip, host_key.get_name(), host_key)
        client._host_keys_filename = None  # We don't have a host keys file

        # Authenticate
        if not transport.is_authenticated():
            transport.auth_password(username=username, password=password)

        if transport.is_authenticated():
            logger.debug("Authentication successful!")
            logger.debug("Connection successful!")
            # You can open a session or perform other actions here
        else:
            logger.error("Authentication failed.")
    except Exception as e:
        logger.error(f"Connection failed: {e}")
    finally:
        transport.close()
        logger.debug("Connection closed.")

def main(stdscr):
    # Initialize colors
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)     # Red text
    curses.init_pair(2, curses.COLOR_GREEN, -1)   # Green text
    curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Yellow text
    curses.init_pair(4, curses.COLOR_CYAN, -1)    # Cyan text
    curses.init_pair(5, curses.COLOR_MAGENTA, -1) # Magenta text
    curses.init_pair(6, curses.COLOR_WHITE, -1)   # White text

    curses.curs_set(0)  # Hide cursor
    stdscr.nodelay(True)  # Make getch() non-blocking
    stdscr.clear()
    height, width = stdscr.getmaxyx()
    left_width = width // 2 - 1
    right_width = width - left_width - 3
    # Create Left Panel for Connection Profile
    left_panel = curses.newwin(height - 2, left_width, 1, 1)
    left_panel.box()
    # Create Right Panel for Log Output
    log_win_height = height - 2
    log_win = curses.newwin(log_win_height, right_width, 1, left_width + 2)
    log_win.box()
    stdscr.refresh()
    left_panel.refresh()
    log_win.refresh()

    # Input fields
    fields = [
        {'label': 'IP Address:', 'value': '192.168.1.1'},
        {'label': 'Port:', 'value': '22'},
        {'label': 'Username:', 'value': 'root'},
        {'label': 'Password:', 'value': ''},
    ]
    # Algorithm selections
    selections = [
        {'label': 'Host Key Algorithms', 'options': all_hostkey_algs},
        {'label': 'KEX Algorithms', 'options': all_kex_algs},
        {'label': 'Ciphers', 'options': all_ciphers},
        {'label': 'MACs', 'options': all_macs},
    ]
    # Initialize selected options (all selected by default)
    for sel in selections:
        sel['selected'] = [True] * len(sel['options'])

    # Indexes to keep track of navigation
    current_field = 0  # Index of the current field or selection
    edit_mode = False  # Whether we're editing text input
    alg_select_mode = False  # Whether we're selecting algorithms
    current_alg_option = 0  # Current algorithm option index
    current_alg_category = 0  # Current algorithm category index

    # Set up logging
    log_queue = queue.Queue()
    log_messages = []
    # Configure the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # Clear existing handlers
    logger.handlers = []
    # Create handlers
    queue_handler = logging.handlers.QueueHandler(log_queue)
    file_handler = logging.FileHandler('session_log.txt')
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    # Add handlers to logger
    logger.addHandler(queue_handler)
    logger.addHandler(file_handler)

    # Ensure Paramiko logs at DEBUG level
    logging.getLogger('paramiko').setLevel(logging.DEBUG)
    logging.getLogger('paramiko.transport').setLevel(logging.DEBUG)

    # Log window scrolling
    log_start_line = 0  # Starting line index for display
    max_log_lines = log_win_height - 4  # Adjust for borders and header

    # To check if user has manually scrolled
    user_scrolled = False

    # Main loop
    while True:
        # Handle key inputs
        key = stdscr.getch()
        if key != -1:
            if alg_select_mode:
                # Algorithm selection mode
                if key == curses.KEY_UP:
                    current_alg_option = (current_alg_option - 1) % len(selections[current_alg_category]['options'])
                elif key == curses.KEY_DOWN:
                    current_alg_option = (current_alg_option + 1) % len(selections[current_alg_category]['options'])
                elif key == ord(' '):
                    # Toggle selection
                    sel = selections[current_alg_category]
                    sel['selected'][current_alg_option] = not sel['selected'][current_alg_option]
                elif key in (curses.KEY_ENTER, 10, 13):
                    # Exit algorithm selection mode
                    alg_select_mode = False
                    user_scrolled = False  # Reset dynamic scrolling
                elif key == ord('\t'):
                    # Exit algorithm selection mode
                    alg_select_mode = False
                    user_scrolled = False  # Reset dynamic scrolling
            elif edit_mode:
                # Editing an input field
                curses.echo()
                curses.curs_set(1)
                field = fields[current_field]
                left_panel.move(3 + current_field * 2, 15)
                left_panel.clrtoeol()
                field['value'] = left_panel.getstr().decode()
                curses.noecho()
                curses.curs_set(0)
                edit_mode = False
                user_scrolled = False  # Reset dynamic scrolling
            else:
                # Normal mode
                if key == curses.KEY_UP:
                    current_field = (current_field - 1) % (len(fields) + len(selections))
                    user_scrolled = False  # Reset dynamic scrolling
                elif key == curses.KEY_DOWN:
                    current_field = (current_field + 1) % (len(fields) + len(selections))
                    user_scrolled = False  # Reset dynamic scrolling
                elif key in (curses.KEY_ENTER, 10, 13):
                    if current_field < len(fields):
                        # Enter edit mode
                        edit_mode = True
                    else:
                        # Enter algorithm selection mode
                        alg_select_mode = True
                        current_alg_category = current_field - len(fields)
                        current_alg_option = 0
                elif key == curses.KEY_PPAGE:
                    # Page up
                    log_start_line = max(0, log_start_line - max_log_lines)
                    user_scrolled = True
                elif key == curses.KEY_NPAGE:
                    # Page down
                    if log_start_line + max_log_lines < len(log_messages):
                        log_start_line += max_log_lines
                    else:
                        log_start_line = max(0, len(log_messages) - max_log_lines)
                    user_scrolled = True
                elif key == ord('c') or key == ord('C'):
                    # Connect
                    params = {
                        'ip': fields[0]['value'],
                        'port': fields[1]['value'],
                        'username': fields[2]['value'],
                        'password': fields[3]['value'],
                        'host_key_algs': [alg for idx, alg in enumerate(all_hostkey_algs) if selections[0]['selected'][idx]],
                        'kex_algs': [alg for idx, alg in enumerate(all_kex_algs) if selections[1]['selected'][idx]],
                        'ciphers': [alg for idx, alg in enumerate(all_ciphers) if selections[2]['selected'][idx]],
                        'macs': [alg for idx, alg in enumerate(all_macs) if selections[3]['selected'][idx]],
                    }
                    threading.Thread(target=connect, args=(params, log_queue), daemon=True).start()
                    user_scrolled = False  # Reset dynamic scrolling
                elif key == ord('l') or key == ord('L'):
                    # Clear log
                    log_messages.clear()
                    log_start_line = 0
                    user_scrolled = False
                elif key == ord('s') or key == ord('S'):
                    # Save log
                    with open('session_log_dump.txt', 'w') as f:
                        for msg, _ in log_messages:
                            f.write(msg + '\n')
                    log_messages.append(("Session log saved to session_log_dump.txt", curses.color_pair(6)))
                    if not user_scrolled:
                        log_start_line = max(0, len(log_messages) - max_log_lines)
                elif key == ord('q') or key == ord('Q'):
                    # Quit
                    break

        # Check log queue and update log messages
        while not log_queue.empty():
            record = log_queue.get()
            msg = record.getMessage()
            if record.levelno == logging.ERROR:
                msg_color = curses.color_pair(1)  # Red
            elif record.levelno == logging.WARNING:
                msg_color = curses.color_pair(3)  # Yellow
            else:
                msg_color = curses.color_pair(6)  # White
            log_messages.append((msg, msg_color))
            if not user_scrolled:
                log_start_line = max(0, len(log_messages) - max_log_lines)

        # Update log window
        log_win.erase()
        log_win.box()
        log_win.addstr(1, 2, "Session Log Output", curses.color_pair(5))
        y = 2
        display_messages = log_messages[log_start_line:log_start_line + max_log_lines]
        for line, color in display_messages:
            wrapped_lines = textwrap.wrap(line, right_width - 2)
            for wrap_line in wrapped_lines:
                if y >= log_win_height - 1:
                    break
                log_win.addstr(y, 1, wrap_line, color)
                y += 1
        log_win.refresh()

        # Draw left panel
        left_panel.erase()
        left_panel.box()
        left_panel.addstr(1, 2, "Connection Profile", curses.color_pair(5))

        # Draw input fields
        y = 3
        for idx, field in enumerate(fields):
            if idx == current_field and not edit_mode and not alg_select_mode:
                attr = curses.A_REVERSE | curses.color_pair(2)
            else:
                attr = curses.color_pair(6)
            left_panel.addstr(y, 2, field['label'], attr)
            left_panel.addstr(y, 15, field['value'])
            y += 2

        # Draw algorithm selections
        for idx, sel in enumerate(selections):
            if idx + len(fields) == current_field and not edit_mode and not alg_select_mode:
                attr = curses.A_REVERSE | curses.color_pair(2)
            else:
                attr = curses.color_pair(6)
            left_panel.addstr(y, 2, sel['label'], attr)
            selected_count = sum(sel['selected'])
            left_panel.addstr(y, 20, f"{selected_count} selected")
            y += 2

        # Instructions
        left_panel.addstr(height - 9, 2, "[↑/↓] Navigate  [Enter] Edit/Select", curses.color_pair(4))
        left_panel.addstr(height - 8, 2, "[C] Connect  [L] Clear Log  [S] Save Log", curses.color_pair(4))
        left_panel.addstr(height - 7, 2, "[Q] Quit  [PgUp/PgDn] Scroll Log", curses.color_pair(4))

        # Handle algorithm selection UI
        if alg_select_mode:
            left_panel.erase()
            left_panel.box()
            sel = selections[current_alg_category]
            left_panel.addstr(1, 2, sel['label'] + " (Space to select, Enter to confirm)", curses.color_pair(5))
            for idx, option in enumerate(sel['options']):
                if idx == current_alg_option:
                    attr = curses.A_REVERSE | curses.color_pair(2)
                else:
                    attr = curses.color_pair(6)
                checked = '[X]' if sel['selected'][idx] else '[ ]'
                left_panel.addstr(3 + idx, 2, f"{checked} {option}", attr)
            left_panel.refresh()
        else:
            left_panel.refresh()

        # Small sleep to prevent high CPU usage
        time.sleep(0.05)

    # Reset cursor visibility on exit
    curses.curs_set(1)

if __name__ == "__main__":
    curses.wrapper(main)
