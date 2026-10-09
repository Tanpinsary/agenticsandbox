// Acceptance fixture for the installed DSH MCP/tool runtime, without a model.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

const output = process.argv[2];
const dsh = fs.realpathSync('/opt/homebrew/bin/dsh');
const packagePath = path.resolve(path.dirname(dsh), '../package.json');
const req = createRequire(packagePath);
const YAML = req('yaml');
const load = name => import(pathToFileURL(req.resolve(name)));
const [{ Context }, { default: SystemPrompt }, { default: ToolRuntime }, mcp, { PROFILE_TEMPLATES }] = await Promise.all([
  load('@deepseek-ai/cordis'), load('@deepseek-ai/dsh-system-prompt'),
  load('@deepseek-ai/dsh-tools'), load('@deepseek-ai/dsh-mcp-client'), load('@deepseek-ai/dsh-app-boot'),
]);
const patch = YAML.parseDocument(fs.readFileSync(path.join(os.homedir(), '.dsh/cordis.patch.yml'), 'utf8'));
if (patch.errors.length) throw Error('Invalid DSH global patch');
const entries = patch.toJS().flatMap(row => row.insert ?? []);
const registrations = entries.filter(row => row.config?.serverName === 'agenticsandbox');
if (registrations.length !== 1) throw Error('Expected exactly one global agenticsandbox registration');
const entry = registrations[0];
const checks = {};
const report = { client: 'dsh', version: JSON.parse(fs.readFileSync(packagePath)).version,
  backend: 'ssh_docker', real_model_used: false, production_approved: false, checks };
let task;
let ctx;
let failure;
let calls = 0;

function findRegistrations(tree, found = []) {
  if (!tree || typeof tree !== 'object') return found;
  if (tree.name === '@deepseek-ai/dsh-mcp-client' && tree.config?.serverName === 'agenticsandbox') found.push(tree);
  for (const value of Object.values(tree)) findRegistrations(value, found);
  return found;
}

try {
  // Use the real launcher to confirm the home patch reaches every profile,
  // without booting a UI, model, or agent. Never print the composed config.
  const profiles = Object.keys(PROFILE_TEMPLATES);
  if (!profiles.length) throw Error('No installed DSH profile templates');
  report.profiles = profiles;
  for (const cwd of [process.cwd(), '/']) {
    for (const profile of profiles) {
      const text = execFileSync(dsh, ['--profile', profile, '--dump-config'], { cwd, encoding: 'utf8', timeout: 15000,
        stdio: ['ignore', 'pipe', 'pipe'] });
      const doc = YAML.parseDocument(text);
      if (doc.errors.length) throw Error('Invalid composed DSH profile: ' + profile);
      const matches = findRegistrations(doc.toJS());
      checks[`global_${profile}_${cwd === '/' ? 'root' : 'other_directory'}`] = matches.length === 1 &&
        matches[0].config.command === entry.config.command;
    }
  }

  ctx = new Context();
  ctx.plugin(SystemPrompt, {});
  ctx.plugin(ToolRuntime, { mode: 'native' });
  ctx.plugin(mcp, entry.config);
  const deadline = Date.now() + 20000;
  while ((ctx.tools?.schemas().filter(s => s.name.startsWith('mcp__agenticsandbox__')).length ?? 0) < 20) {
    if (Date.now() >= deadline) throw Error('DSH MCP discovery timed out');
    await delay(25);
  }
  const schemas = ctx.tools.schemas().filter(s => s.name.startsWith('mcp__agenticsandbox__'));
  checks.dsh_discovered_20_tools = schemas.length === 20;

  async function call(rawName, args) {
    const prefix = 'mcp__agenticsandbox__' + rawName.replace(/[^a-zA-Z0-9_]/g, '_') + '_';
    const matches = schemas.filter(s => s.name.startsWith(prefix));
    if (matches.length !== 1) throw Error('DSH tool missing or ambiguous: ' + rawName);
    const result = await ctx.tools.execute({ callId: randomUUID(), name: matches[0].name,
      arguments: args, signal: AbortSignal.timeout(120000) });
    calls++;
    if (result.isError) throw Error('DSH tool failed: ' + rawName + ': ' + JSON.stringify(result.content));
    return JSON.parse(result.value.content.find(c => c.type === 'text').text);
  }

  report.tool_runtime = '@deepseek-ai/dsh-tools';
  checks.connected_installed_controller = (await call('sandbox.info', {})).backend === 'ssh_docker';
  const created = await call('task.create', { runtime: 'agentic', network: 'none', role: 'scratch',
    purpose: 'DSH global MCP installation acceptance', files: { include: ['**'], exclude: [] }, ttl_minutes: 10 });
  task = created.id;
  checks.created_real_docker_sandbox = created.isolated === true && created.isolation_basis === 'docker_controls';
  const input = "require('fs').writeFileSync('result.txt','dsh-mcp-ready\\n'); console.log(JSON.stringify({uid:process.getuid(),cwd:process.cwd(),home:process.env.HOME}));\n";
  await call('task.write', { task_id: task, path: 'audit.js', data: Buffer.from(input).toString('base64') });
  const execution = await call('task.exec', { task_id: task, argv: ['node', 'audit.js'], timeout_seconds: 15 });
  const limit = Date.now() + 45000;
  let record;
  while (Date.now() < limit) {
    const status = await call('task.status', { task_id: task });
    record = status.execution_records.find(r => r.id === execution.execution_id);
    if (!['starting', 'running'].includes(record.state)) break;
    await delay(150);
  }
  if (record?.state !== 'completed' || record.exit_code !== 0) throw Error('DSH sandbox execution failed');
  const logs = await call('task.logs', { task_id: task, execution_id: execution.execution_id, cursor: 0 });
  const identity = JSON.parse(Buffer.from(logs.data, 'base64').toString());
  checks.executed_with_restricted_uid_and_home = identity.uid === 10001 && identity.cwd === '/workspace/repo' && identity.home === '/workspace/home';
  const result = await call('task.read', { task_id: task, path: 'result.txt' });
  checks.write_execute_read = Buffer.from(result.data, 'base64').toString() === 'dsh-mcp-ready\n';
  await call('task.destroy', { task_id: task, abandon: true });
  task = undefined;
  checks.own_task_destroyed = true;
} catch (error) {
  failure = error;
  report.error = error.message;
} finally {
  if (task && ctx?.tools) {
    const schema = ctx.tools.schemas().find(s => s.name.startsWith('mcp__agenticsandbox__task_destroy_'));
    const result = await ctx.tools.execute({ callId: randomUUID(), name: schema.name,
      arguments: { task_id: task, abandon: true }, signal: AbortSignal.timeout(120000) });
    checks.own_task_destroyed = !result.isError;
  }
  if (ctx) await ctx.fiber.dispose();
  report.tool_calls = calls;
  report.passed = !failure && Object.values(checks).every(Boolean);
  report.check_count = Object.keys(checks).length;
  if (output) fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  if (!report.passed) process.exitCode = 1;
}
