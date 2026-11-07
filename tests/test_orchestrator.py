import io
import json
import os
import tempfile
import time
import unittest
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

import yaml

from ctf_orchestrator.core import (detect_milestones, FLAG_RE, build_prompt, file_manifest, find_disagreements, invoke, isolated_invoke,
                                   execute_tasks, koth_command, koth_route, load_config,
                                   normalize_koth_target, parse_koth_prompt, prune_run_workspaces, RunResult,
                                   soften_text)
from ctf_orchestrator.cli import main, _sync_artifacts, receipt_summary, _workspace_arg


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.workspace = self.root / 'input'
        self.workspace.mkdir()
        (self.workspace / 'evidence.txt').write_text('original')

    def tearDown(self):
        self.tmp.cleanup()

    def client(self, name, source, client='agy'):
        p = self.root / name
        p.write_text('#!/usr/bin/env python3\n' + source)
        p.chmod(0o755)
        return {'id': name, 'client': client, 'command': str(p), 'model': 'test/model',
                'model_verified': True, 'max_parallel': 1, 'directions': ['general']}

    def test_permission_denial_even_with_exit_zero(self):
        agent = self.client('denied', '''import sys
print('no output produced — a tool required the command permission that headless mode cannot prompt for, so it was auto-denied', file=sys.stderr)
''')
        result = invoke(agent, {'id': 'x', 'prompt': 'test'}, self.workspace, 5, '')
        self.assertEqual(result.status, 'blocked_permissions')
        self.assertEqual(result.refusal, 'technical_failure')

    def test_empty_stream_not_success(self):
        agent = self.client('empty', 'print("")\n')
        result = invoke(agent, {'id': 'x', 'prompt': 'test'}, self.workspace, 5, '')
        self.assertEqual(result.status, 'error')

    def test_aggregate_retry_isolates_source_and_records_hashes(self):
        bad = self.client('bad', 'import sys\nprint("auto-denied", file=sys.stderr)\n')
        good = self.client('good', '''import json
from pathlib import Path
Path('evidence.txt').write_text('changed')
Path('output.txt').write_text('artifact')
print(json.dumps({'event':'result','result':{'status':'SUCCESS','response':'FLAG: picoCTF{proof}'}}))
''')
        config = {'agents': [bad, good], 'max_parallel': 1, 'timeout_seconds': 5}
        data = {'tasks': [{'id': 'x', 'direction': 'general', 'prompt': 'test'}]}
        report = execute_tasks(config, data, self.root / 'run', self.workspace)
        self.assertEqual([r['status'] for r in report['results']], ['blocked_permissions', 'success'])
        self.assertEqual((self.workspace / 'evidence.txt').read_text(), 'original')
        recovered = report['results'][1]
        self.assertEqual(recovered['flags'], ['picoCTF{proof}'])
        self.assertEqual({a['path'] for a in recovered['artifacts']}, {'evidence.txt', 'output.txt'})
        self.assertEqual(len(recovered['inputs'][0]['sha256']), 64)

    def test_hung_process_is_terminated(self):
        agent = self.client('hung', 'import time\ntime.sleep(10)\n')
        agent['idle_timeout_seconds'] = 1
        start = time.monotonic()
        result = invoke(agent, {'id': 'x', 'prompt': 'test'}, self.workspace, 5, '')
        self.assertEqual(result.status, 'hung')
        self.assertLess(time.monotonic() - start, 4)

    def test_learn_uses_scored_benchmarks_only(self):
        config = self.root / 'agents.yaml'
        config.write_text("metrics_file: metrics.yaml\nagents:\n  - id: learner\n    client: codex\n    model: test-model\n    metrics: {}\n")
        report = self.root / 'report.json'
        report.write_text(json.dumps({'benchmark': True, 'results': [
            {'agent_id':'learner','model':'test-model','direction':'general','status':'success',
             'duration_seconds':12, 'evaluation':{'correctness':'correct'}},
            {'agent_id':'learner','model':'test-model','direction':'general','status':'success',
             'duration_seconds':18, 'evaluation':{'correctness':'incorrect'}}]}))
        self.assertEqual(main(['--config', str(config), 'learn', str(report)]), 0)
        learned = load_config(config)['agents'][0]['metrics']['general']
        self.assertEqual(learned['quality'], 0.5)
        self.assertEqual(learned['samples'], 2)
        self.assertEqual(learned['median_seconds'], 15)

    def test_workspace_ignores_symlinks_to_external_paths(self):
        (self.workspace / 'outside').symlink_to(self.root / 'other')
        agent = self.client('echoer', "import json\nprint(json.dumps({'event':'result','result':{'status':'SUCCESS','response':'ok'}}))\n")
        result = isolated_invoke(agent, {'id': 'x', 'prompt': 'test'}, self.workspace, self.root / 'attempt', 5, '')
        self.assertEqual(result.status, 'success')
        self.assertFalse((Path(result.workspace) / 'outside').exists())

    def test_distinct_flags_are_disagreement(self):
        args = dict(task_id='same', client='agy', model='m', direction='general', status='success', duration_seconds=1)
        a = RunResult(agent_id='a', response='picoCTF{a}', **args)
        b = RunResult(agent_id='b', response='picoCTF{b}', **args)
        self.assertIn('different flags', find_disagreements([a, b])[0]['reason'])

    def test_flag_extraction_does_not_join_a_prefix_to_later_prose(self):
        text = 'Prefix `picoCTF{example_` (23 bytes). Append `}` then picoCTF{example_42}'
        self.assertEqual([m.group(0) for m in FLAG_RE.finditer(text)], ['picoCTF{example_42}'])

    def test_codex_brief_includes_pace_doctrine(self):
        agent = {'id': 'codex', 'client': 'codex', 'model': 'm', 'model_verified': True}
        task = {'id': 'x', 'prompt': 'Probe the target and report findings.'}
        prompt, style, _ = build_prompt(agent, task, 'Local files only')
        self.assertEqual(style, 'standard')
        self.assertIn('PACE:', prompt)
        self.assertIn('Never park a command in a background session and poll it', prompt)
        # The doctrine is codex-only: AGY briefs must not grow.
        agy = {'id': 'agy', 'client': 'agy', 'model': 'm', 'model_verified': True}
        agy_prompt, _, _ = build_prompt(agy, task, 'Local files only')
        self.assertNotIn('PACE:', agy_prompt)

    def test_agy_default_prompt_keeps_brief_out_of_prompt(self):
        agent = {'id': 'agy', 'client': 'agy', 'model': 'm', 'model_verified': True}
        task = {'id': 'x', 'prompt': 'Authorized DownUnderCTF 2024 review. Provide the exploit chain.'}
        prompt, style, changes = build_prompt(agent, task, 'Local files only')
        self.assertEqual((style, changes), ('casual', ['brief -> DEFEX_TASK.md']))
        self.assertIn('DEFEX_TASK.md', prompt)
        self.assertNotIn('DownUnderCTF', prompt)
        self.assertNotIn('exploit chain', prompt.lower())
        self.assertIn('purely hypothetically', prompt)

    def test_lab_review_softens_brief(self):
        agent = {'id': 'agy', 'client': 'agy', 'model': 'm', 'model_verified': True}
        task = {'id': 'x', 'prompt': 'Return the exploit chain and JSON payloads; keep `exploit.py` unchanged. '
                                      'Find picoCTF{abc_123} in /flag.txt and report the flag value.'}
        prompt, style, changes = build_prompt(agent, task, 'Local files only', style='lab_review')
        self.assertEqual(style, 'lab_review')
        self.assertNotIn('exploit chain', prompt.lower())
        self.assertNotIn('payloads', prompt.lower())
        self.assertNotIn('capture-the-flag', prompt.lower())
        self.assertIn('solution path', prompt)
        self.assertIn('`exploit.py`', prompt)
        self.assertIn('picoCTF{abc_123}', prompt)
        self.assertIn('/flag.txt', prompt)
        self.assertIn('marker value', prompt)
        self.assertTrue(changes)

    def test_isolated_invoke_writes_brief_file_outside_manifest(self):
        agent = self.client('briefcheck', '''import json
from pathlib import Path
print(json.dumps({'event':'result','result':{'status':'SUCCESS','response':'FLAG: picoCTF{ok}' if Path('DEFEX_TASK.md').is_file() else 'missing'}}))
''')
        result = isolated_invoke(agent, {'id': 'x', 'prompt': 'secret organizer brief'}, self.workspace,
                                 self.root / 'attempt', 5, 'local scope')
        self.assertEqual(result.status, 'success')
        self.assertEqual(result.flags, ['picoCTF{ok}'])
        self.assertEqual(result.artifacts, [])
        self.assertNotIn('DEFEX_TASK.md', {item['path'] for item in result.inputs})
        self.assertEqual((Path(result.workspace) / 'DEFEX_TASK.md').read_text(),
                         '# Task\n\nsecret organizer brief\n\n## Scope\n\nlocal scope\n')

    def test_softening_handles_sentence_ends_and_filenames(self):
        text = 'Find the flag. Keep flag.txt and /flag and exploit_dev.py unchanged.'
        softened, _ = soften_text(text)
        self.assertEqual(softened, 'Find the marker. Keep flag.txt and /flag and exploit_dev.py unchanged.')

    def test_standard_clients_keep_original_wording(self):
        agent = {'id': 'codex', 'client': 'codex', 'model': 'm', 'model_verified': True}
        prompt, style, changes = build_prompt(agent, {'id': 'x', 'prompt': 'exploit chain wording'}, '')
        self.assertEqual((style, changes), ('standard', []))
        self.assertIn('Task: exploit chain wording', prompt)

    def test_minimal_style_is_available_as_fallback(self):
        agent = {'id': 'agy', 'client': 'agy', 'model': 'm', 'model_verified': True}
        prompt, style, _ = build_prompt(agent, {'id': 'x', 'prompt': 'text', 'prompt_style': 'lab_minimal'}, '')
        self.assertEqual(style, 'lab_minimal')
        self.assertLess(len(prompt.split()), 200)

    def test_provider_block_is_not_success(self):
        response = "This request was blocked by Gemini's filters. Please try rephrasing your prompt."
        agent = self.client('blocked', f"import json\nprint(json.dumps({{'event':'result','result':{{'status':'SUCCESS','response':{response!r}}}}}))\n")
        result = invoke(agent, {'id': 'x', 'prompt': 'test'}, self.workspace, 5, '')
        self.assertEqual(result.status, 'blocked_policy')
        self.assertEqual(result.refusal, 'policy_refusal')

    def test_model_refusal_without_tools_is_policy_block(self):
        response = 'Sorry, I cannot fulfill your request. I cannot provide exploit chains or attack steps.'
        agent = self.client('refused', f"import json\nprint(json.dumps({{'event':'result','result':{{'status':'SUCCESS','response':{response!r}}}}}))\n")
        result = invoke(agent, {'id': 'x', 'prompt': 'test'}, self.workspace, 5, '')
        self.assertEqual(result.status, 'blocked_policy')
        self.assertEqual(result.prompt_style, 'casual')

    def test_delegate_uses_configured_fallback_after_policy_block(self):
        response = "This request was blocked by Gemini's filters. Please try rephrasing your prompt."
        blocked = self.client('blocked', f"import json\nprint(json.dumps({{'event':'result','result':{{'status':'SUCCESS','response':{response!r}}}}}))\n")
        alt = self.client('alt', "import json\nprint(json.dumps({'event':'result','result':{'status':'SUCCESS','response':'FLAG: picoCTF{alt}'}}))\n")
        blocked['fallback'] = {'command': alt['command'], 'model': 'alt/model', 'model_verified': True}
        config_file = self.root / 'agents.yaml'
        config_file.write_text(yaml.safe_dump({'agents': [blocked], 'timeout_seconds': 5}))
        previous = os.environ.get('XDG_STATE_HOME')
        os.environ['XDG_STATE_HOME'] = str(self.root / 'state')
        os.environ['DEFEX_MIN_FREE_GB'] = '0'
        out = io.StringIO()
        try:
            with mock.patch('sys.stdin', io.StringIO('review this package')), redirect_stdout(out):
                code = main(['--config', str(config_file), 'delegate', 'agy', '--workspace', str(self.workspace)])
        finally:
            if previous is None:
                os.environ.pop('XDG_STATE_HOME', None)
            else:
                os.environ['XDG_STATE_HOME'] = previous
            os.environ.pop('DEFEX_MIN_FREE_GB', None)
        payload = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload['status'], 'success')
        self.assertEqual(payload['model'], 'alt/model')
        self.assertEqual(payload['flags'], ['picoCTF{alt}'])
        self.assertEqual(len(payload['attempts']), 3)

    def test_parallel_verifier_uses_different_client(self):
        a = self.client('a', 'print("")\n', client='agy')
        b = self.client('b', 'print("")\n', client='codex')
        report = execute_tasks({'agents': [a, b]}, {'tasks': [{'id':'x','prompt':'x'}]},
                               self.root / 'run', self.workspace, dry_run=True, verify=True)
        self.assertEqual(len(report['results']), 2)
        self.assertNotEqual(report['assignments']['x'], report['reviewers']['x'])
        self.assertIsNone(report['summary']['by_direction']['general']['success_rate'])

    def test_koth_prompt_routes_to_tool_command(self):
        completed = mock.Mock(returncode=0, stdout='{"ok": true}', stderr='')
        with mock.patch('ctf_orchestrator.core.subprocess.run', return_value=completed) as run:
            routed = koth_route('koth:10.0.0.5')
        self.assertEqual(routed['route'], 'koth')
        self.assertEqual(routed['target'], '10.0.0.5')
        # The tool path resolves per environment (DEFEX_KOTH_TOOL, repo-local
        # ctf-tool/, then ~/test/ctf-tool) — assert the shape, not the path.
        from ctf_orchestrator.core import _koth_tool
        self.assertEqual(routed['command'],
                         ['python3', _koth_tool(), 'koth', 'auto', '10.0.0.5', '--json'])
        self.assertEqual(run.call_args.args[0], routed['command'])
        self.assertIn('recon', routed['delegation']['note'])
        self.assertEqual(routed['returncode'], 0)

    def test_koth_prompt_normalizes_scheme_and_trailing_slash(self):
        self.assertEqual(parse_koth_prompt('koth: 10.0.0.5'), '10.0.0.5')
        self.assertEqual(parse_koth_prompt('  koth http://10.0.0.5/  '), '10.0.0.5')
        self.assertEqual(normalize_koth_target('https://host:8080//'), 'host:8080')
        self.assertIsNone(parse_koth_prompt('review this package'))
        self.assertIsNone(koth_route('review this package'))
        self.assertEqual(koth_command('10.0.0.5')[-2:], ['10.0.0.5', '--json'])

    def test_koth_prompt_rejects_prose_and_non_host_tokens(self):
        # A relay task that merely starts with the word "KotH" must stay an
        # ordinary delegation (incident 2026-11-04: target parsed as "CTF,"
        # and the delegate died instantly on koth auto).
        self.assertIsNone(parse_koth_prompt('KotH CTF, single authorized target 10.10.222.240 — probe port 82 LFI'))
        self.assertIsNone(parse_koth_prompt('koth: CTF,'))
        self.assertIsNone(parse_koth_prompt('koth run!'))
        # Valid hosts still route, ports included.
        self.assertEqual(parse_koth_prompt('koth 10.10.222.240'), '10.10.222.240')
        self.assertEqual(parse_koth_prompt('KOTH:10.10.222.240'), '10.10.222.240')
        self.assertEqual(parse_koth_prompt('koth http://box.thm.local:8080/'), 'box.thm.local:8080')
        self.assertEqual(parse_koth_prompt('koth localhost'), 'localhost')

    # --- Relay hardening (RELAY-RETRO-2026-11-03) ---

    AGY_SUCCESS = "import json\nprint(json.dumps({'event':'result','result':{'status':'SUCCESS','response':'ok'}}))\n"
    AGY_BLOCKED = ("import json\n"
                   "print(json.dumps({'event':'result','result':{'status':'SUCCESS','response':"
                   "\"This request was blocked by Gemini's filters. Please try rephrasing.\"}}))\n")

    @contextmanager
    def isolated_state(self):
        previous = os.environ.get('XDG_STATE_HOME')
        os.environ['XDG_STATE_HOME'] = str(self.root / 'state')
        try:
            yield self.root / 'state' / 'defex-ctf' / 'runs'
        finally:
            if previous is None:
                os.environ.pop('XDG_STATE_HOME', None)
            else:
                os.environ['XDG_STATE_HOME'] = previous

    def delegate(self, agent_scripts, *extra_args, stdin_text='test task', env=None, with_workspace=True):
        """Run `defex-ctf delegate` against fake clients; returns (code, parsed stdout, stderr)."""
        agents = [self.client(name, script, client=client)
                  for name, script, client in agent_scripts]
        config_file = self.root / 'agents.yaml'
        config_file.write_text(yaml.safe_dump({'agents': agents, 'timeout_seconds': 10}))
        out, err = io.StringIO(), io.StringIO()
        # The headroom floor targets the real state filesystem; test temp
        # directories can sit on a small tmpfs.
        merged_env = {'DEFEX_MIN_FREE_GB': '0', **(env or {})}
        saved = {k: os.environ.get(k) for k in merged_env}
        os.environ.update(merged_env)
        try:
            with mock.patch('sys.stdin', io.StringIO(stdin_text)), \
                    redirect_stdout(out), redirect_stderr(err):
                code = main(['--config', str(config_file), 'delegate', agent_scripts[0][2],
                             *(('--workspace', str(self.workspace)) if with_workspace else ()),
                             *extra_args])
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        return code, json.loads(out.getvalue()) if out.getvalue().strip() else None, err.getvalue()

    def test_delegate_workspace_defaults_to_scratch(self):
        # 2026-11-05: --workspace is optional. Omitting it means an empty
        # private scratch dir — nothing is copied, the client's artifacts stay
        # accounted via the manifest diff.
        script = self.AGY_SUCCESS + "\nimport pathlib\npathlib.Path('note.md').write_text('x')\n"
        with self.isolated_state() as runs:
            code, payload, _ = self.delegate([('gem', script, 'agy')], with_workspace=False)
            receipt = json.loads((runs / payload['receipt'] / 'receipt.json').read_text())
        self.assertEqual(code, 0)
        self.assertEqual(payload['status'], 'success')
        self.assertEqual(receipt['workspace_mode'], 'scratch')
        self.assertEqual([a['path'] for a in payload['artifacts']], ['note.md'])
        # No copy happened: the input evidence file never reached the client.
        self.assertNotIn('evidence.txt', [a['path'] for a in payload.get('inputs', [])])
        self.assertFalse((Path(payload['workspace']) / 'evidence.txt').exists())

    def test_delegate_workspace_means_direct_no_copy(self):
        # 2026-11-05: a passed workspace IS the working directory — no copy.
        script = self.AGY_SUCCESS + "\nimport pathlib\npathlib.Path('direct.md').write_text('x')\n"
        with self.isolated_state() as runs:
            code, payload, _ = self.delegate([('gem', script, 'agy')])
            receipt = json.loads((runs / payload['receipt'] / 'receipt.json').read_text())
        self.assertEqual(code, 0)
        self.assertEqual(receipt['workspace_mode'], 'direct')
        # The client wrote straight into the real directory.
        self.assertEqual(Path(payload['workspace']), self.workspace.resolve())
        self.assertTrue((self.workspace / 'direct.md').exists())
        self.assertEqual(payload['artifacts'], [])
        self.assertIsNone(payload.get('sync_baseline'))

    def test_isolated_invoke_scratch_and_direct_modes(self):
        script = self.AGY_SUCCESS + "\nimport pathlib\npathlib.Path('note.md').write_text('x')\n"
        agent = self.client('cdx', script)
        dest = self.root / 'attempt'
        result = isolated_invoke(agent, {'id': 'x', 'prompt': 'test'}, None, dest, 5, '',
                                 workspace_mode='scratch')
        self.assertEqual(result.status, 'success')
        self.assertTrue((dest / 'workspace' / 'note.md').exists())
        self.assertEqual([a['path'] for a in result.artifacts], ['note.md'])
        self.assertFalse((dest / 'workspace' / 'evidence.txt').exists())
        direct_dest = self.root / 'attempt2'
        result2 = isolated_invoke(agent, {'id': 'x', 'prompt': 'test'}, self.workspace, direct_dest, 5, '',
                                  workspace_mode='direct')
        self.assertEqual(result2.status, 'success')
        self.assertEqual(Path(result2.workspace), self.workspace.resolve())
        self.assertTrue((self.workspace / 'note.md').exists())
        self.assertFalse((direct_dest / 'workspace').exists())
        self.assertEqual(result2.artifacts, [])
        self.assertIsNone(result2.sync_baseline)

    def test_delegate_parser_accepts_optional_workspace(self):
        from ctf_orchestrator.cli import parser
        args = parser().parse_args(['delegate', 'codex'])
        self.assertIsNone(args.workspace)
        self.assertFalse(args.direct)
        args2 = parser().parse_args(['delegate', 'codex', '--workspace', str(self.workspace), '--direct'])
        self.assertTrue(args2.direct)  # accepted no-op for older relay plugins

    def test_milestone_expiry_preserves_marker_and_dedupe(self):
        seen = set()
        old = detect_milestones("codex", "uid=0(root)", seen, event_time=99, run_ended_at=1000, expiry_minutes=15)
        fresh = detect_milestones("codex", "uid=0(root)", seen, event_time=900, run_ended_at=1000, expiry_minutes=15)
        self.assertEqual(old, [])
        self.assertEqual(len(fresh), 1)
        self.assertTrue(fresh[0].startswith("(unverified)"))
        self.assertEqual(detect_milestones("codex", "uid=0(root)", seen), [])

    def test_receipt_summary_fields(self):
        summary = receipt_summary("a"*32, {"front":"web", "attempts":[{"status":"success", "client":"codex", "model":"m", "duration_seconds":3, "artifacts":[{"path":"x"}]}]}, self.root/"receipt.json")
        self.assertEqual((summary["status"], summary["client"], summary["model"], summary["front"]), ("success", "codex", "m", "web"))
        self.assertEqual(summary["artifacts"], [{"path":"x"}])
        self.assertEqual(summary["receipt_path"], str(self.root/"receipt.json"))

    def test_workspace_validation_and_auto_create(self):
        created = self.root/"created"
        self.assertEqual(_workspace_arg(str(created)), created.resolve())
        with self.assertRaises(ValueError): _workspace_arg(str(self.root/"missing"), create=False)
        with self.assertRaises(ValueError): _workspace_arg(str(Path.home()))
        with self.assertRaises(ValueError): _workspace_arg(".")
        oversized = self.root/"oversized"; oversized.mkdir(); (oversized/"huge").write_bytes(b"x"*(2*1024*1024))
        # Delegate runs directly in the directory — no size scan; the 1 GB
        # guard stays on the check_size=True default (run/batch copy path).
        self.assertEqual(_workspace_arg(str(oversized), check_size=False), oversized.resolve())

    def test_hold_watch_loopback_fixture(self):
        import socket, threading
        server=socket.socket(); server.bind(("127.0.0.1",0)); server.listen()
        thread=threading.Thread(target=lambda: server.accept()[0].close(), daemon=True); thread.start()
        config=self.root/"agents.yaml"; config.write_text(yaml.safe_dump({"agents":[]}))
        log=self.root/"watch.log"
        with redirect_stdout(io.StringIO()): code=main(["--config",str(config),"hold-watch","--port",f"127.0.0.1:{server.getsockname()[1]}","--interval","0.01","--count","1","--log",str(log)])
        server.close(); self.assertEqual(code,0); self.assertIn("open",log.read_text())

    def test_deadline_kills_sleeping_client(self):
        sleeper="import time\ntime.sleep(5)\n"
        with self.isolated_state():
            started=time.monotonic(); code,payload,_=self.delegate([("slow",sleeper,"codex")],"--deadline","1")
        self.assertLess(time.monotonic()-started,4)
        self.assertEqual(code,1); self.assertEqual(payload["status"],"timeout")
        self.assertEqual(payload["attempts"][-1]["status"],"timeout")

    def test_policy_block_does_not_reroute_to_another_client(self):
        with self.isolated_state():
            code, payload, _ = self.delegate(
                [('gem', self.AGY_BLOCKED, 'agy'), ('cdx', self.AGY_SUCCESS, 'codex')])
        self.assertEqual(code, 1)
        self.assertEqual(payload['status'], 'blocked_policy')
        # Both attempts stay on the requested AGY agent (the built-in casual
        # reframe retry); a policy stance is provider-level, so no codex attempt.
        self.assertTrue(payload['attempts'])
        self.assertTrue(all(a['agent_id'] == 'gem' for a in payload['attempts']))
        self.assertTrue(all(a['client'] == 'agy' for a in payload['attempts']))

    def seed_thread_receipt(self, runs_dir, thread, status='success', question=''):
        run_dir = runs_dir / ('a' * 32)
        run_dir.mkdir(parents=True, exist_ok=True)
        attempt = {'task_id': 'a' * 32, 'agent_id': 'gem', 'client': 'agy', 'status': status,
                   'client_thread': thread, 'question': question, 'error': '', 'duration_seconds': 1.0}
        (run_dir / 'receipt.json').write_text(json.dumps({'run_id': 'a' * 32, 'attempts': [attempt]}))

    def test_resume_of_finished_success_thread_is_refused(self):
        with self.isolated_state() as runs_dir:
            self.seed_thread_receipt(runs_dir, 'thread-1')
            code, payload, err = self.delegate([('gem', self.AGY_SUCCESS, 'agy')],
                                               '--resume', 'thread-1')
        self.assertEqual(code, 2)
        self.assertIsNone(payload)
        self.assertIn('--new-task', err)
        self.assertIn('thread-1', err)

    def test_resume_allowed_for_open_question_and_new_task(self):
        with self.isolated_state() as runs_dir:
            self.seed_thread_receipt(runs_dir, 'thread-q', question='which scope?')
            code, payload, _ = self.delegate([('gem', self.AGY_SUCCESS, 'agy')],
                                             '--resume', 'thread-q', stdin_text='the web scope only')
            self.assertEqual(code, 0)
            self.assertEqual(payload['status'], 'success')

            self.seed_thread_receipt(runs_dir, 'thread-done')
            code, payload, _ = self.delegate([('gem', self.AGY_SUCCESS, 'agy')],
                                             '--resume', 'thread-done', '--new-task')
            self.assertEqual(code, 0)
            self.assertEqual(payload['status'], 'success')

    def test_disk_headroom_refuses_before_any_run_dir(self):
        with self.isolated_state() as runs_dir, \
                mock.patch('ctf_orchestrator.core.shutil.disk_usage',
                           return_value=mock.Mock(free=1024)):
            code, payload, err = self.delegate([('cdx', self.AGY_SUCCESS, 'codex')],
                                               env={'DEFEX_MIN_FREE_GB': '0.001'})
        self.assertEqual(code, 2)
        self.assertIsNone(payload)
        self.assertIn('headroom', err)
        self.assertFalse(runs_dir.exists() and any(runs_dir.iterdir()))

    def test_file_manifest_whitelists_report_files(self):
        (self.workspace / 'a.py').write_text('x')
        (self.workspace / 'b.bin').write_bytes(b'x')
        (self.workspace / 'c.txt').write_text('report')
        (self.workspace / 'sub').mkdir()
        (self.workspace / 'sub' / 'd.json').write_text('{}')
        self.assertEqual([m['path'] for m in file_manifest(self.workspace)],
                         ['c.txt', 'evidence.txt', 'sub/d.json'])

    def test_file_manifest_budget_truncates(self):
        for index in range(5):
            (self.workspace / f'r{index}.txt').write_text('x')
        with mock.patch('ctf_orchestrator.core.time.monotonic', side_effect=[0, 1000]):
            self.assertEqual(file_manifest(self.workspace, budget_seconds=5), [])

    def test_prune_removes_workspace_copies_and_aged_receipts(self):
        runs = self.root / 'runs'
        fresh = runs / ('b' * 32)
        (fresh / 'attempt-1' / 'workspace').mkdir(parents=True)
        (fresh / 'attempt-1' / 'workspace' / 'evidence.txt').write_text('x')
        (fresh / 'receipt.json').write_text('{}')
        aged = runs / ('c' * 32)
        aged.mkdir()
        (aged / 'receipt.json').write_text('{}')
        stamp = time.time() - 40 * 86400
        os.utime(aged / 'receipt.json', (stamp, stamp))
        summary = prune_run_workspaces(runs, keep_days=30)
        self.assertEqual(summary['removed_workspaces'], 1)
        self.assertEqual(summary['removed_runs'], 1)
        self.assertFalse((fresh / 'attempt-1' / 'workspace').exists())
        self.assertTrue((fresh / 'receipt.json').exists())
        self.assertFalse(aged.exists())

    def test_sync_artifacts_copies_new_or_changed_files(self):
        """Reports and new binaries both sync; unchanged non-reports are skipped."""
        target = self.root / 'out'
        target.mkdir()
        result = mock.Mock(workspace=str(self.workspace))
        (self.workspace / 'keep.txt').write_text('ok')
        (self.workspace / 'tool.bin').write_bytes(b'x')
        (self.workspace / 'stale.bin').write_bytes(b'old')
        # New files are absent from the baseline; stale.bin is unchanged.
        stale = (self.workspace / 'stale.bin').stat()
        result.sync_baseline = {'stale.bin': (stale.st_size, stale.st_mtime_ns)}
        result.artifacts = [{'path': 'keep.txt', 'sha256': 'a'}, {'path': 'tool.bin', 'sha256': 'b'}]
        copied = _sync_artifacts(result, target)
        self.assertIn(str(target / 'keep.txt'), copied)
        self.assertTrue((target / 'tool.bin').exists())
        self.assertFalse((target / 'stale.bin').exists())

    def test_sync_artifacts_enforces_size_limits(self):
        target = self.root / 'out'
        target.mkdir()
        result = mock.Mock(workspace=str(self.workspace))
        (self.workspace / 'big.bin').write_bytes(b'x' * 2048)
        result.sync_baseline = {}
        result.artifacts = []
        with mock.patch.dict(os.environ, {'DEFEX_SYNC_MAX_FILE_MB': '0'}):
            copied = _sync_artifacts(result, target)
        self.assertEqual(copied, [])
        self.assertFalse((target / 'big.bin').exists())

    def test_delegate_runs_directly_and_prunes_run_dir(self):
        # 2026-11-05: a passed workspace IS the working directory — the client
        # edits the real files; only the run dir (receipt) is left behind.
        writer = ("from pathlib import Path\n"
                  "Path('evidence.txt').write_text('changed')\n" + self.AGY_SUCCESS)
        with self.isolated_state():
            code, payload, _ = self.delegate([('gem', writer, 'agy')])
            run_dir = Path(payload['receipt_path']).parent
        self.assertEqual(code, 0)
        self.assertEqual((self.workspace / 'evidence.txt').read_text(), 'changed')
        self.assertFalse((run_dir / 'attempt-1' / 'workspace').exists())
        self.assertTrue((run_dir / 'receipt.json').exists())

    def test_wait_for_client_slot_emits_queue_events(self):
        # A queued delegation must be visible in its relay transcript instead
        # of looking like a dead subagent with an empty child session.
        import fcntl
        from ctf_orchestrator.cli import wait_for_client_slot
        events = self.root / 'events.jsonl'
        held = open(self.root / 'codex-0.lock', 'a+')
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        waiter = open(self.root / 'codex-0.lock', 'a+')
        now = [1000.0]

        def fake_sleep(_seconds):
            now[0] += 30.0

        got = wait_for_client_slot([waiter], 'codex', events_jsonl=str(events),
                                   deadline=1100.0, clock=lambda: now[0], sleep=fake_sleep)
        self.assertEqual(got, 'deadline')
        rows = [json.loads(line) for line in events.read_text().splitlines()]
        texts = [row['text'] for row in rows]
        self.assertTrue(any(t.startswith('slot wait: all 1 codex slots busy - queued') for t in texts))
        self.assertTrue(any('still queued for codex' in t for t in texts))
        # No acquisition note when the deadline expires before a slot frees.
        self.assertFalse(any(t.startswith('slot acquired') for t in texts))
        waiter.close()
        held.close()

    def test_wait_for_client_slot_free_slot_is_silent(self):
        import fcntl
        from ctf_orchestrator.cli import wait_for_client_slot
        events = self.root / 'events.jsonl'
        lock = open(self.root / 'codex-0.lock', 'a+')
        got = wait_for_client_slot([lock], 'codex', events_jsonl=str(events),
                                   clock=lambda: 0.0, sleep=lambda s: None)
        self.assertIs(got, lock)
        # An instantly free slot writes nothing: no queue chatter.
        self.assertFalse(events.exists())
        lock.close()


    def test_resolve_codex_account_balances_five_hour_limit(self):
        from ctf_orchestrator import core

        def account(id, label, status="ready", used=None, busy=0, last=0, with_auth=True):
            path = self.root / "accounts" / id
            path.mkdir(parents=True, exist_ok=True)
            if with_auth:
                (path / "auth.json").write_text("{}")
            limits = {"primary": {"usedPercent": used}} if used is not None else None
            return {"id": id, "label": label, "status": status,
                    "busyTasks": busy, "lastUsedAt": last,
                    "limits": limits}

        fixture = [account("a1", "Main", used=22),
                   account("a2", "Backup", used=3),
                   account("a3", "LoggedOut", status="login_required", used=0),
                   account("a4", "NoQuota"),
                   account("a5", "NoAuth", used=1, with_auth=False)]
        fake = mock.Mock(returncode=0, stdout=json.dumps(fixture))
        with mock.patch.dict(os.environ, {"DEFEX_CODEXCTL_DATA": str(self.root)}), \
                mock.patch.object(core.subprocess, "run", return_value=fake):
            picked = core.resolve_codex_account()
        self.assertEqual((picked["id"], picked["used_percent"]), ("a2", 3))
        self.assertTrue(picked["dir"].endswith("/accounts/a2"))

        # Least used wins ties on busy tasks, then on least-recently-used.
        fixture2 = [account("b1", "X", used=5, busy=2, last=90),
                    account("b2", "Y", used=5, busy=0, last=10)]
        fake2 = mock.Mock(returncode=0, stdout=json.dumps(fixture2))
        with mock.patch.dict(os.environ, {"DEFEX_CODEXCTL_DATA": str(self.root)}), \
                mock.patch.object(core.subprocess, "run", return_value=fake2):
            self.assertEqual(core.resolve_codex_account()["id"], "b2")

        # Aggregator missing/failing → None (caller keeps the default CODEX_HOME).
        with mock.patch.object(core.subprocess, "run",
                               side_effect=OSError("no codexctl")):
            self.assertIsNone(core.resolve_codex_account())

    def test_codex_resume_pins_thread_account(self):
        # A resumed thread must run under the CODEX_HOME that owns its rollout:
        # the receipt attempt records the account dir, _thread_state returns it.
        from ctf_orchestrator.core import _thread_state
        runs = self.root / "runs"
        runs.mkdir()
        account_dir = str(self.root / "acc" / "a2")
        for name, thread, acct in (("aggregated", "th1", account_dir),
                                    ("default-home", "th2", "")):
            (runs / name).mkdir()
            (runs / name / "receipt.json").write_text(json.dumps(
                {"run_id": name, "attempts": [{"client_thread": thread, "status": "question",
                                               "question": "q?", "task_id": name, "account": acct}]}))
        self.assertEqual(_thread_state(runs, "th1")["account"], account_dir)
        self.assertEqual(_thread_state(runs, "th2")["account"], "")
        self.assertEqual(_thread_state(runs, "missing"), None)

    def test_invoke_sets_codex_account_from_aggregator(self):
        from ctf_orchestrator import core
        account = {"id": "a2", "label": "Backup", "dir": str(self.root / "acc" / "a2"),
                   "used_percent": 3}
        agent = {'id': 'codex', 'client': 'codex', 'model': 'm', 'model_verified': True,
                 'account_aggregator': 'codexctl'}
        captured = {}

        def fake_run(command, cwd, env, timeout, *args, **kwargs):
            captured['env'] = dict(env)
            captured['command'] = list(command)
            return 0, json.dumps({"type": "thread.started", "thread_id": "t1"}) + "\n", "", ""

        with mock.patch.object(core, "resolve_codex_account", return_value=account), \
                mock.patch.object(core, "_run_process", side_effect=fake_run), \
                mock.patch.object(core, "client_available", return_value=(True, "ok")):
            result = core.invoke(agent, {'id': 'x', 'prompt': 'test'}, self.workspace, 5, '')
        self.assertEqual(captured['env'].get("CODEX_HOME"), account["dir"])
        self.assertEqual(result.account, account["dir"])


if __name__ == '__main__':
    unittest.main()
