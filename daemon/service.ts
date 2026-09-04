import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BASE_URL, CONFIG_FILE, DATA } from './paths.ts';

export type Launcher = { node: string; script: string };

const RUN_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
const RUN_VALUE = 'cc-hush';
const LAUNCHD_LABEL = 'com.cc-hush.daemon';
const SYSTEMD_UNIT = 'cc-hush.service';

const run = (file: string, args: string[]) => execFileSync(file, args, { stdio: 'pipe', encoding: 'utf8' });
const tryRun = (file: string, args: string[]) => { try { return run(file, args); } catch { return ''; } };
const xml = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
const uid = () => process.getuid?.() ?? 0;

export const windowsLauncherVbs = ({ node, script }: Launcher) => `CreateObject("WScript.Shell").Run """${node}"" ""${script}"" start --log", 0, False\r\n`;

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

const vbsFile = path.join(DATA, 'start.vbs');
const plistFile = path.join(os.homedir(), 'Library', 'LaunchAgents', `${LAUNCHD_LABEL}.plist`);
const unitFile = path.join(os.homedir(), '.config', 'systemd', 'user', SYSTEMD_UNIT);

export function installService(launcher: Launcher): string {
  switch (process.platform) {
    case 'win32': {
      fs.writeFileSync(vbsFile, windowsLauncherVbs(launcher));
      run('reg', ['add', RUN_KEY, '/v', RUN_VALUE, '/t', 'REG_SZ', '/d', `wscript.exe //B //Nologo "${vbsFile}"`, '/f']);
      return `logon entry "${RUN_VALUE}" registered in ${RUN_KEY}, hidden launcher ${vbsFile}`;
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
    case 'win32': return run('wscript.exe', ['//B', '//Nologo', vbsFile]);
    case 'darwin': return run('launchctl', ['kickstart', `gui/${uid()}/${LAUNCHD_LABEL}`]);
    default: return run('systemctl', ['--user', 'start', SYSTEMD_UNIT]);
  }
}

export function uninstallService() {
  switch (process.platform) {
    case 'win32': tryRun('reg', ['delete', RUN_KEY, '/v', RUN_VALUE, '/f']); fs.rmSync(vbsFile, { force: true }); return;
    case 'darwin': tryRun('launchctl', ['bootout', `gui/${uid()}/${LAUNCHD_LABEL}`]); fs.rmSync(plistFile, { force: true }); return;
    default: tryRun('systemctl', ['--user', 'disable', '--now', SYSTEMD_UNIT]); fs.rmSync(unitFile, { force: true }); tryRun('systemctl', ['--user', 'daemon-reload']); return;
  }
}

export const claudeSettingsFile = () => path.join(process.env.CLAUDE_CONFIG_DIR ?? path.join(os.homedir(), '.claude'), 'settings.json');

export const configuredBaseUrl = (settingsJson: string | undefined): string | undefined => (settingsJson ? JSON.parse(settingsJson) : {}).env?.ANTHROPIC_BASE_URL;

export function mergeBaseUrl(settingsJson: string | undefined, chain = false): { text?: string; upstream?: string; note: string } {
  const settings = settingsJson ? JSON.parse(settingsJson) : {};
  const current = settings.env?.ANTHROPIC_BASE_URL;
  if (current === BASE_URL) return { note: `ANTHROPIC_BASE_URL already points at ${BASE_URL}.` };
  if (current && !chain) return { note: `ANTHROPIC_BASE_URL is "${current}", left unchanged. To chain it, put it as "upstream" in ${CONFIG_FILE} and set ANTHROPIC_BASE_URL to ${BASE_URL} in ${claudeSettingsFile()}. Until then nothing is redacted.` };
  settings.env = { ...settings.env, ANTHROPIC_BASE_URL: BASE_URL };
  const text = JSON.stringify(settings, null, 2) + '\n';
  if (current) return { text, upstream: current, note: `ANTHROPIC_BASE_URL set to ${BASE_URL} in ${claudeSettingsFile()}; the daemon forwards to ${current} (upstream in ${CONFIG_FILE}). Restart Claude Code.` };
  return { text, note: `ANTHROPIC_BASE_URL set to ${BASE_URL} in ${claudeSettingsFile()}. Restart Claude Code.` };
}
