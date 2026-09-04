import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BASE_URL, DATA } from './paths.ts';

export type Launcher = { node: string; script: string };

const TASK_NAME = 'cc-hush';
const LAUNCHD_LABEL = 'com.cc-hush.daemon';
const SYSTEMD_UNIT = 'cc-hush.service';

const run = (file: string, args: string[]) => execFileSync(file, args, { stdio: 'pipe', encoding: 'utf8' });
const tryRun = (file: string, args: string[]) => { try { return run(file, args); } catch { return ''; } };
const xml = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
const uid = () => process.getuid?.() ?? 0;

export const windowsTaskXml = ({ node, script }: Launcher, user: string) => `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>${xml(user)}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>${xml(user)}</UserId><LogonType>S4U</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>${xml(node)}</Command><Arguments>&quot;${xml(script)}&quot; start --log</Arguments></Exec></Actions>
</Task>
`;

export const launchdPlist = ({ node, script }: Launcher) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array><string>${xml(node)}</string><string>${xml(script)}</string><string>start</string><string>--log</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
</dict></plist>
`;

export const systemdUnit = ({ node, script }: Launcher) => `[Unit]
Description=cc-hush privacy daemon

[Service]
ExecStart="${node}" "${script}" start --log
Restart=on-failure

[Install]
WantedBy=default.target
`;

const taskXmlFile = path.join(DATA, 'cc-hush.task.xml');
const plistFile = path.join(os.homedir(), 'Library', 'LaunchAgents', `${LAUNCHD_LABEL}.plist`);
const unitFile = path.join(os.homedir(), '.config', 'systemd', 'user', SYSTEMD_UNIT);

export function installService(launcher: Launcher): string {
  switch (process.platform) {
    case 'win32': {
      const user = `${process.env.USERDOMAIN ?? os.hostname()}\\${os.userInfo().username}`;
      fs.writeFileSync(taskXmlFile, '﻿' + windowsTaskXml(launcher, user), 'utf16le');
      run('schtasks', ['/create', '/f', '/tn', TASK_NAME, '/xml', taskXmlFile]);
      return `scheduled task "${TASK_NAME}" registered, runs at logon of ${user}`;
    }
    case 'darwin': {
      fs.mkdirSync(path.dirname(plistFile), { recursive: true });
      fs.writeFileSync(plistFile, launchdPlist(launcher));
      tryRun('launchctl', ['bootout', `gui/${uid()}/${LAUNCHD_LABEL}`]);
      run('launchctl', ['bootstrap', `gui/${uid()}`, plistFile]);
      return `launch agent ${plistFile} loaded`;
    }
    default: {
      fs.mkdirSync(path.dirname(unitFile), { recursive: true });
      fs.writeFileSync(unitFile, systemdUnit(launcher));
      run('systemctl', ['--user', 'daemon-reload']);
      run('systemctl', ['--user', 'enable', SYSTEMD_UNIT]);
      return `systemd user unit ${unitFile} enabled (headless machines also need: loginctl enable-linger)`;
    }
  }
}

export function startService() {
  switch (process.platform) {
    case 'win32': return run('schtasks', ['/run', '/tn', TASK_NAME]);
    case 'darwin': return run('launchctl', ['kickstart', `gui/${uid()}/${LAUNCHD_LABEL}`]);
    default: return run('systemctl', ['--user', 'start', SYSTEMD_UNIT]);
  }
}

export function uninstallService() {
  switch (process.platform) {
    case 'win32': tryRun('schtasks', ['/delete', '/f', '/tn', TASK_NAME]); fs.rmSync(taskXmlFile, { force: true }); return;
    case 'darwin': tryRun('launchctl', ['bootout', `gui/${uid()}/${LAUNCHD_LABEL}`]); fs.rmSync(plistFile, { force: true }); return;
    default: tryRun('systemctl', ['--user', 'disable', '--now', SYSTEMD_UNIT]); fs.rmSync(unitFile, { force: true }); tryRun('systemctl', ['--user', 'daemon-reload']); return;
  }
}

export const claudeSettingsFile = () => path.join(process.env.CLAUDE_CONFIG_DIR ?? path.join(os.homedir(), '.claude'), 'settings.json');

export function mergeBaseUrl(settingsJson: string | undefined): { text?: string; note: string } {
  const settings = settingsJson ? JSON.parse(settingsJson) : {};
  const current = settings.env?.ANTHROPIC_BASE_URL;
  if (current === BASE_URL) return { note: `ANTHROPIC_BASE_URL already points at ${BASE_URL}.` };
  if (current) return { note: `ANTHROPIC_BASE_URL is "${current}", left unchanged. If that is another proxy, put it as "upstream" in ${path.join(DATA, 'config.json')} and set ANTHROPIC_BASE_URL to ${BASE_URL} in ${claudeSettingsFile()}. Until then nothing is redacted.` };
  settings.env = { ...settings.env, ANTHROPIC_BASE_URL: BASE_URL };
  return { text: JSON.stringify(settings, null, 2) + '\n', note: `ANTHROPIC_BASE_URL set to ${BASE_URL} in ${claudeSettingsFile()}. Restart Claude Code.` };
}
