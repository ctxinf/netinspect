#!/usr/bin/env python3
"""Local-only CLI lifecycle checks: python3 scripts/cli-smoke.py /path/to/netinspect."""
import json
import os
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

    def launch(args):
        log = tempfile.TemporaryFile(mode='w+t')
        process = subprocess.Popen([binary, *args], cwd=directory, env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log, text=True)
        processes.append(process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            log.seek(0)
            text = log.read()
            match = re.search(r'或用 (.+) 强制停止', text)
            if match:
                assert text.index('目标程序已结束') < match.start(), text
                assert '或用 Ctrl+C 直接结束' in text, text
                command = shlex.split(match[1])
                return process, command[command.index('--url') + 1], command[command.index('--token') + 1], command
            panel = re.search(r'· 面板: (http://[^\s]+)', text)
            if panel and 'sleep' in args:
                req = urllib.request.Request(panel[1] + '/api/control', headers={'X-Netinspect-Control': '1'})
                with http.open(req, timeout=2) as response:
                    token = json.load(response)['token']
                assert '强制停止' not in text, text
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
        assert run(['--help']).returncode == 0
        for invalid in [['run', 'true'], ['--mode', 'observe', 'true']]:
            result = run(invalid)
            assert result.returncode != 0 and '必须添加 --' in result.stderr, result
        result = run(['--keep-alive', '0', '--', 'sh', '-c', 'printf "%s" "$1"', 'sh', '--mode=observe'])
        assert result.returncode == 0 and result.stdout == '--mode=observe', result
        assert '会话      ' not in result.stderr and '模式      ' not in result.stderr
        assert '强制停止' not in result.stderr
        startup = result.stderr.split('──────────────── 目标程序输出')[0]
        assert startup.strip().splitlines()[-1].startswith('· 面板: http://'), result.stderr
        assert '\x1b[' not in result.stderr, 'redirected logs contain ANSI escapes'
        assert all(not line.startswith((' ', '\t')) for line in result.stderr.splitlines()), result.stderr
        assert '──────────────── 目标程序输出 ────────────────' in result.stderr
        assert result.stderr.index('目标程序输出结束') < result.stderr.index('目标程序已结束'), result.stderr
        assert run(['--version']).stdout.strip().startswith('netinspect ')
        assert run(['run', '--keep-alive', '0', '--', 'sh', '-c', 'exit 7']).returncode == 7
        result = run(['--keep-alive', '200ms', '--', 'true'])
        assert result.returncode == 0 and '面板已关闭' in result.stderr, result
        # No arguments displays help without starting a target or dashboard.
        Path(directory, '.netinspect.json').write_text('{"keep_alive":"0"}')
        shortcut = run(['sh', '-c', 'printf shortcut', '--mode', 'observe'])
        assert shortcut.returncode == 0 and shortcut.stdout == 'shortcut', shortcut
        result = run([], input='printf "%s" "$NETINSPECT_SOCKS_PORT"\nexit\n')
        assert result.returncode == 0 and "--mode MODE" in result.stdout and "面板:" not in result.stderr, result
        for args in (["--mode"], ["--mode", "rplace"]):
            result = run(args)
            assert result.returncode != 0 and "preload（默认）| ptrace | netns | observe" in result.stderr, result
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
        assert result.returncode == 0 and result.stderr.count('尝试嵌套 ptrace') == 1, result
        result = run(['--keep-alive', '0', '--', 'sh', '-c',
                      'unset LD_PRELOAD; exec sleep 2.2'])
        assert result.returncode == 0 and result.stderr.count('当前目标 PID 未加载 libnetinspect.so') == 1, result
        result = run(['--keep-alive', '0', '--', 'sleep', '2.2'])
        assert result.returncode == 0 and '未加载 libnetinspect.so' not in result.stderr, result

        print('CLI smoke passed: defaults, passthrough, exit codes, timer, shell, concurrent ports, stop isolation, web shutdown')
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()
