#!/usr/bin/env python3
"""Local-only CLI lifecycle checks: python3 scripts/cli-smoke.py /path/to/netinspect."""
import json
import os
import pty
import socketserver
import threading
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

binary = str(Path(sys.argv[1]).resolve())
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
processes = []


def request(url, path='/api/session', token=None):
    headers = {'Authorization': 'Bearer ' + token} if token else {}
    req = urllib.request.Request(url + path, headers=headers, method='POST' if token else 'GET')
    with http.open(req, timeout=2) as response:
        return json.load(response)


with tempfile.TemporaryDirectory(prefix='netinspect-cli-') as directory:
    env = {**os.environ, 'XDG_CONFIG_HOME': directory, 'SHELL': '/bin/sh'}
    Path(directory, 'netinspect').mkdir()
    Path(directory, 'netinspect', 'config.json').write_text('{"open_browser":false}')

    def run(args, **kw):
        return subprocess.run([binary, *args], cwd=directory, env=env, text=True,
                              capture_output=True, timeout=10, **kw)

    def terminal_help(no_color=False):
        master, slave = pty.openpty()
        terminal_env = {**env, 'TERM': 'xterm-256color'}
        terminal_env.pop('NO_COLOR', None)
        if no_color:
            terminal_env['NO_COLOR'] = '1'
        process = subprocess.Popen([binary, '--help'], cwd=directory, env=terminal_env,
                                   stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.PIPE)
        os.close(slave)
        chunks = []
        try:
            while True:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(master)
            assert process.wait(timeout=5) == 0
        return b''.join(chunks)

    def launch(args):
        log = tempfile.TemporaryFile(mode='w+t')
        process = subprocess.Popen([binary, *args], cwd=directory, env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log, text=True)
        processes.append(process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            log.seek(0)
            text = log.read()
            match = re.search(r'Or run (.+)', text)
            if match:
                assert text.index('Target exited') < match.start(), text
                assert 'Or press Ctrl+C to stop' in text, text
                command = shlex.split(match[1])
                return process, command[command.index('--url') + 1], command[command.index('--token') + 1], command
            panel = re.search(r'· Dashboard: (http://[^\s]+)', text)
            if panel and 'sleep' in args:
                req = urllib.request.Request(panel[1] + '/api/control', headers={'X-Netinspect-Control': '1'})
                with http.open(req, timeout=2) as response:
                    token = json.load(response)['token']
                assert 'Or run' not in text, text
                return process, panel[1], token, None
            if process.poll() is not None:
                raise AssertionError(text)
            time.sleep(.03)
        raise AssertionError('startup timeout')

    def ended(url):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if request(url)['session']['ended_at']:
                return
            time.sleep(.03)
        raise AssertionError('target did not end')

    try:
        help_result = run(['--help'])
        assert help_result.returncode == 0 and 'alias ni=netinspect' in help_result.stdout
        assert 'Local config:' in help_result.stdout and '[missing]' in help_result.stdout
        assert '[exists]' in help_result.stdout and '\x1b[' not in help_result.stdout
        assert b'\x1b[1;32mUsage:' in terminal_help()
        assert b'\x1b[' not in terminal_help(no_color=True)
        for topic in ['run', 'stop', 'skills', 'init-config', 'version']:
            assert run(['help', topic]).returncode == 0
        assert 'Session control token' in run(['stop', '--help']).stdout
        assert run(['skills', 'list']).returncode == 0
        assert 'HTTP API reference' in run(['skills', 'get', 'core', '--full']).stdout
        # Existing configuration must survive initialization unchanged.
        config_path = Path(directory, 'netinspect', 'config.json')
        before = config_path.read_bytes()
        assert run(['init-config']).returncode != 0
        assert config_path.read_bytes() == before
        config_path.unlink()
        assert run(['init-config']).returncode == 0
        assert json.loads(config_path.read_text())['mode'] == 'preload'
        config_path.write_bytes(before)
        # Both inherited markers and /proc ancestry block nested capture.
        for mode in ['preload', 'ptrace', 'observe']:
            nested = run(['--mode', mode, '--keep-alive', '0', '--', binary,
                          '--keep-alive', '0', '--', 'true'])
            assert nested.returncode != 0 and 'nested netinspect' in nested.stderr, nested
        nested = run(['--mode', 'observe', '--keep-alive', '0', '--', 'env',
                      '-u', 'NETINSPECT_ACTIVE_SESSION', binary,
                      '--keep-alive', '0', '--', 'true'])
        assert nested.returncode != 0 and 'ancestor PID' in nested.stderr, nested
        for invalid in [['run', 'true'], ['--mode', 'observe', 'true']]:
            result = run(invalid)
            assert result.returncode != 0 and 'add -- before the target command' in result.stderr, result
        result = run(['--keep-alive', '0', '--', 'sh', '-c', 'printf "%s" "$1"', 'sh', '--mode=observe'])
        assert result.returncode == 0 and result.stdout == '--mode=observe', result
        assert 'Session      ' not in result.stderr and 'Mode      ' not in result.stderr
        assert 'Or run' not in result.stderr
        startup = result.stderr.split('──────────────── Target output')[0]
        assert startup.strip().splitlines()[-1].startswith('· Dashboard: http://'), result.stderr
        assert '\x1b[' not in result.stderr, 'redirected logs contain ANSI escapes'
        assert all(not line.startswith((' ', '\t')) for line in result.stderr.splitlines()), result.stderr
        assert '──────────────── Target output ────────────────' in result.stderr
        assert result.stderr.index('End of target output') < result.stderr.index('Target exited'), result.stderr
        assert run(['--version']).stdout.strip().startswith('netinspect ')
        assert run(['run', '--keep-alive', '0', '--', 'sh', '-c', 'exit 7']).returncode == 7
        result = run(['--keep-alive', '200ms', '--', 'true'])
        assert result.returncode == 0 and 'Dashboard stopped' in result.stderr, result
        # No arguments displays help without starting a target or dashboard.
        Path(directory, '.netinspect.json').write_text('{"keep_alive":"0"}')
        shortcut = run(['sh', '-c', 'printf shortcut', '--mode', 'observe'])
        assert shortcut.returncode == 0 and shortcut.stdout == 'shortcut', shortcut
        result = run([], input='printf "%s" "$NETINSPECT_SOCKS_PORT"\nexit\n')
        assert result.returncode == 0 and "--mode <MODE>" in result.stdout and "Dashboard:" not in result.stderr, result
        for args in (["--mode"], ["--mode", "rplace"]):
            result = run(args)
            assert result.returncode != 0 and "preload (default)| ptrace | netns | observe" in result.stderr, result
        Path(directory, '.netinspect.json').unlink()

        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        first, url1, token1, stop1 = launch(['--port', str(port), '--', 'true'])
        second, url2, token2, stop2 = launch(['--port', str(port), '--mode', 'observe', '--', 'sh', '-c', 'exit 9'])
        assert int(url2.rsplit(':', 1)[1]) == port + 1, (url1, url2)
        ended(url1)
        ended(url2)
        assert first.poll() is None and second.poll() is None
        try:
            request(url2, '/api/shutdown', token1)
            raise AssertionError('wrong instance token accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 403
        stopped = subprocess.run(stop1, env=env, capture_output=True, timeout=5)
        assert stopped.returncode == 0, stopped.stderr
        assert first.wait(timeout=5) == 0
        assert second.poll() is None
        # Same API used by the browser button.
        request(url2, '/api/shutdown', token2)
        assert second.wait(timeout=5) == 9
        active, active_url, active_token, _ = launch(['--mode', 'observe', '--', 'sleep', '30'])
        try:
            request(active_url, '/api/shutdown', active_token)
            raise AssertionError('running target was stopped')
        except urllib.error.HTTPError as error:
            assert error.code == 409
        active.terminate()  # Forward SIGTERM to target; dashboard should survive.
        ended(active_url)
        assert active.poll() is None
        request(active_url, '/api/shutdown', active_token)
        assert active.wait(timeout=5) == 143
        result = run(['--mode', 'ptrace', '--keep-alive', '0', '--', 'sh', '-c', 'exit 13'])
        assert result.returncode == 13, result
        result = run(['--mode', 'ptrace', '--keep-alive', '0', '--', sys.executable,
                      '-c', 'import ctypes; ctypes.CDLL(None).ptrace(0, 0, 0, 0)'])
        assert result.returncode == 0 and result.stderr.count('attempted nested ptrace') == 1, result
        result = run(['--keep-alive', '0', '--', 'sh', '-c',
                      'unset LD_PRELOAD; exec sleep 2.2'])
        assert result.returncode == 0 and result.stderr.count('target PID has not loaded libnetinspect.so') == 1, result
        result = run(['--keep-alive', '0', '--', 'sleep', '2.2'])
        assert result.returncode == 0 and 'has not loaded libnetinspect.so' not in result.stderr, result

        class UpstreamHandler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(4)
                line = self.rfile.readline().decode().strip()
                upstream_requests.append(line)
                while self.rfile.readline().strip():
                    pass
                self.wfile.write(b'HTTP/1.1 200 Connected\r\n\r\n')
                self.wfile.flush()
                while self.rfile.readline().strip():
                    pass
                body = b'upstream-routed'
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n' + body)
                self.wfile.flush()

        # Session metadata exposes only the configured proxy endpoint, even before traffic.
        upstream_session, upstream_url, upstream_token, _ = launch([
            '--upstream-proxy', 'http://user:secret@127.0.0.1:3128', '--', 'true'])
        snapshot = request(upstream_url)
        assert snapshot['session']['upstream_proxy'] == 'http://127.0.0.1:3128', snapshot
        assert 'secret' not in json.dumps(snapshot) and 'user:' not in json.dumps(snapshot)
        request(upstream_url, '/api/shutdown', upstream_token)
        assert upstream_session.wait(timeout=5) == 0

        upstream_requests = []
        with socketserver.TCPServer(('127.0.0.1', 0), UpstreamHandler) as proxy_server:
            thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
            thread.start()
            proxy_url = 'http://127.0.0.1:' + str(proxy_server.server_address[1])
            for mode in ['preload', 'ptrace']:
                response = run(['--mode', mode, '--keep-alive', '0', '--upstream-proxy', proxy_url,
                                '--', 'curl', '--silent', '--show-error', '--noproxy', '*',
                                '--max-time', '4', 'http://127.0.0.2:54321/'])
                assert response.returncode == 0 and response.stdout == 'upstream-routed', response
            proxy_server.shutdown()
            thread.join(timeout=5)
        assert upstream_requests == ['CONNECT 127.0.0.2:54321 HTTP/1.1'] * 2, upstream_requests

        print('CLI smoke passed: defaults, passthrough, exit codes, timer, shell, concurrent ports, stop isolation, web shutdown, colors, config, skills, nesting, upstream routing')
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()
