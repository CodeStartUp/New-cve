# CVE-1: cmd.exe `/K` argument injection in the KytyPS5 launcher (RCE)

Status: **confirmed end-to-end against the official release binary**, not just
the source tree.

Scope of this public report: **CVE-1 only.**

Target release: `KytyPS5-2026-10-08-5a88080`
(`https://github.com/KytyPS5/KytyPS5/releases/tag/KytyPS5-2026-10-08-5a88080`)

| property | value |
|---|---|
| release tag | `KytyPS5-2026-10-08-5a88080` |
| git commit | `5a880808`, reported version `0.3.0` (2026.10.08) |
| affected binary | `launcher.exe` (Windows x64, 4,175,360 bytes, SHA256 `4796C3C445818B7957816DD28E1AD375C0E51757BD0DCD983EC3289AB6A9D515`) |
| classification | CWE-78: OS Command Injection |
| sink | `cmd.exe /K "<attacker controlled string>"` |
| impact | arbitrary command execution as the logged-in user |
| preconditions | no game execution required; only a saved configuration value + double-click |
| platform | **Windows only** (see section 6) |
| CVSS 3.1 | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` = **7.8 (High)** |

CVSS rationale: **AV:L** - the payload is a local config file the victim imports
(no network attack surface). **PR:N** - the attacker needs no privileges on the
victim machine. **UI:R** - the victim must import the configuration and launch
the game. **S:U** - the injected command runs as the same user as the launcher,
so no security authority boundary is crossed. **C:H/I:H/A:H** - the command can
read, modify, and destroy anything that user can access. A scope-changed reading
(`S:C`, not applicable here) would score 8.6.

---

## 1. What the bug is

The launcher does not start the emulator directly. On Windows it builds a
*shell command string* and hands it to `cmd.exe` with the `/K` switch:

```
cmd.exe /K ""C:\...\kyty_emulator.exe" "--opt" "value" ... "--game" "..."
```

The purpose of `/K` is to keep the console window open after the emulator
exits. The launcher quotes every token so that paths containing spaces
survive.

Several emulator options take **free-form string values that come from the
user-editable configuration**. Those strings are concatenated into the same
`cmd.exe` command line. If an attacker can place a double quote and an
ampersand into one of those values, cmd.exe's own parser is tricked into
ending the quoted region early, executing the injected command, and then
swallowing the remainder of the line with `rem`.

In the verified payload the injected command runs **before**
`kyty_emulator.exe` ever starts.

---

## 2. Root cause

### 2.1 The escaping function is written for the wrong parser

`src/launcher/src/mainDialog.cpp:389-392`

```cpp
// Quote one token for cmd.exe so paths with spaces survive /K parsing.
static QString WinCmdQuote(QString value) {
	value.replace(QLatin1Char('"'), QStringLiteral("\\\""));
	return QLatin1Char('"') + value + QLatin1Char('"');
}
```

`WinCmdQuote` escapes a literal `"` as `\"`. That is the **C runtime**
CommandLineToArgvW rule: backslash escapes the following quote *when a
program parses its argv*.

**cmd.exe does not implement that rule.** cmd.exe decides whether `&`, `|`,
`<`, `>` and `^` are metacharacters purely by tracking whether the current
character position is inside or outside a double-quoted region, and a `"`
simply toggles that state. A backslash in front of a `"` is, to cmd.exe, just
a backslash followed by a quote.

So for cmd.exe the sequence

```
"....\"&calc&rem \""
 ^    ^ ^
 ON   | +-- toggles OFF, so the following & is OUTSIDE quotes
      +----- backslash is inert
```

The token still *looks* correctly quoted to any C program that later parses
`argv` (that is why the emulator receives the raw value), but cmd.exe has
already been tricked into running `calc`.

### 2.2 The command string is assembled by naive concatenation

`src/launcher/src/mainDialog.cpp:394-401`

```cpp
static QString BuildWinCmdKCommand(const QString& interpreter, const QStringList& args) {
	QString command = WinCmdQuote(QDir::toNativeSeparators(interpreter));
	for (const auto& arg: args) {
		command += QLatin1Char(' ');
		command += WinCmdQuote(arg);
	}
	return command;
}
```

### 2.3 The sink

`src/launcher/src/mainDialog.cpp:438-445`

```cpp
#elif defined(_WIN32)
	{
		// Use nativeArguments so Qt does not re-quote the /K command string.
		process->setProgram(CMD_EXE);
		process->setArguments({});
		process->setNativeArguments(QStringLiteral("/K \"") +
		                            BuildWinCmdKCommand(interpreter, args) + QLatin1Char('"'));
	}
```

`nativeArguments` is passed to `CreateProcessW` **verbatim**; Qt performs no
further escaping (that is the explicit intent of the comment). `CMD_EXE` is
`cmd.exe` (`mainDialog.cpp:53`).

`CREATE_NEW_CONSOLE` is set at `mainDialog.cpp:453`, so a visible console
window is created for the injected command as well.

The vulnerable `/K` quoting path was introduced by
[PR #244](https://github.com/KytyPS5/KytyPS5/pull/244) (fixing
[issue #179](https://github.com/KytyPS5/KytyPS5/issues/179), paths with
spaces) - a functional fix that was never reviewed as a security change.

### 2.4 Which values are attacker-controlled

`src/launcher/src/mainDialog.cpp:217-295` (`CreateEmulatorArgs`) appends
configuration strings unconditionally. The following are unbounded, arbitrary
strings with **no character allow-list**:

| option | configuration field | line |
|---|---|---|
| `--shader-log-folder` | `shader_log_folder` | `mainDialog.cpp:260` |
| `--command-buffer-dump-folder` | `command_buffer_dump_folder` | `mainDialog.cpp:262` |
| `--printf-output-file` | `printf_output_file` | `mainDialog.cpp:264` |
| `--mic` | `audio_input_device` | `mainDialog.cpp:228` |
| `--controller-color` | `controller.color` | `mainDialog.cpp:231` |

`Configuration::SetGameSettings` (`configuration.cpp:110-149`) copies these
fields straight from the imported JSON with **no sanitisation** - compare
`user_name`, which is capped at `MAX_USER_NAME_LENGTH` (16 bytes,
`common/emulatorConfig.h`) but is *not* the only string that reaches the
command line.

`--shader-log-folder` is of particular interest because it is passed
**unconditionally**, even when `shader_log_direction == Silent` (the
default), so no UI interaction beyond clicking the game row is needed.

---

## 3. Attack scenarios

| # | scenario | required access |
|---|---|---|
| A | **Shared configuration**: the launcher's "Game Configs -> Import..." accepts a JSON file. A victim imports a "recommended settings" or "performance preset" from a forum, Discord, or cheat site, then double-clicks a game. | victim interaction (import + launch) |
| B | **Writable `Kyty.ini`**: on Windows the settings file is opened with `QSettings::SystemScope` (`configurationListWidget.cpp:354-357`), i.e. `C:\ProgramData\Kyty\Kyty.ini`. Any process or user that can write this file plants the payload; the next launch by *any* user of the machine executes it. | write access to a shared settings path |
| C | **Already-present foothold**: RMM tool, other low-privilege malware, or a malicious dropper rewrites the ini before the user launches the game - escalating to interactive user code execution. | existing foothold |

The vulnerability does **not** require a malicious game image, does **not**
require the emulator to run, and does **not** require any `EXIT_IF`-gated
code path.

---

## 4. The QSettings INI escaping subtlety (required for a working PoC)

`shader_log_folder` is persisted by Qt `QSettings` in INI format, where
**backslash is the escape character**. Measured behaviour (an internal probe
wrote four candidate values and reported what actually reaches `cmd.exe`):

| written into `Kyty.ini` | effective value received by `WinCmdQuote` | outcome |
|---|---|---|
| `x"&<command>&rem "` (bare quotes) | `x&<command>&rem ` | quotes lost, `&` stays inside `"..."`, **inert** |
| `x\"&<command>&rem \"` (escaped quotes) | `x"&<command>&rem "` | **breakout, injected command executes** |
| `"x&<command>&rem "` (leading quote) | `x&<command>&rem ` | quotes lost, **inert** |
| `x&<command>&rem ` (no quotes) | `x&<command>&rem ` | **inert** |

**The payload must be written with `\"`, not `"`.** QSettings' INI reader
unescapes `\"` to a real `"`, that `"` survives into
`Configuration::shader_log_folder`, and `WinCmdQuote` then re-escapes it to
`\"` - which is exactly the form cmd.exe needs in order to toggle its
quote state at the wrong moment.

Writing a bare `"` into the file produces an inert payload; this is why a
naive attempt appears to "fail" even though the sink is reached.

---

## 5. Verified exploit against the real release binary

### 5.1 Static confirmation

The shipped `launcher.exe` contains the sink. Searching the binary for the
UTF-16LE literal `/K "` finds it at file offset `0x39868E`, pooled in `.rdata`
next to the native-arguments template. Also present:

| literal | file offset |
|---|---|
| `/K "` (UTF-16LE) | `0x39868E` |
| `cmd.exe` | `0x30DF52` |
| `shader-log-folder` | `0x36608A` |
| `Kyty.ini` | `0x30C8E0` |
| `Import game configs` | `0x363FD9` |

### 5.2 Dynamic confirmation (final run, 2026-10-08 11:12)

An automated harness performed the following against the **unmodified
official release build** (scripts are held privately and available to the
maintainers on request):

1. writes the payload into `C:\ProgramData\Kyty\Kyty.ini`
   (`[GlobalConfiguration] shader_log_folder=...`);
2. starts `launcher.exe`;
3. selects the game row "CVE1 Fake Game" and delivers
   `WM_LBUTTONDOWN / WM_LBUTTONDBLCLK / WM_LBUTTONUP` **directly to the
   launcher's own HWND** with client coordinates (this double-click *is*
   the required user interaction - a real victim does it to start a game);
4. captures the spawned `cmd.exe` and checks two marker files;
5. restores `Kyty.ini` and stops all processes.

Result:

```
launcher PID    : 147724
cmd.exe PID     : 190880  (parent 147724)
cmd.exe command line:
cmd.exe  /K ""C:\...\kyty_emulator.exe" "--screen-width" "1280" ...
  ... "--shader-log-folder" "x\"&<INJECTED COMMAND>&rem \"" ...
  ... "--game" "C:/kyty_test/Games/FakeGame/eboot.bin""

[+] MARKER 1 (Windows): C:\Users\Public\cve1_poc.txt
    content: CVE1-PROOF
[+] MARKER 2 (WSL): /tmp/cve1_rce_proof exists inside the Linux distro
Kyty.ini restored: shader_log_folder=_Shaders
[+] RCE CONFIRMED (user-level, Windows + WSL)
```

The important token:

```
"x\"&<INJECTED COMMAND>&rem \""
 ^ ^
 | +-- toggles cmd.exe's quote state OFF
 +---- quote opened by WinCmdQuote
```

Everything after the first `&` is outside quotes, so cmd.exe runs the
injected command, and `rem` then comments out the remainder of the line (the
emulator's own argument tail). Two markers were used: a Windows file (code
ran as the user) and a file inside WSL (the injected command line reaches
the Linux subsystem too).

Only the `\"` variant executes - four payload spellings were tested in one
session and only the escaped-quote form produced a file (see section 4).

### 5.3 Reverse connection (callback)

The same injection chain opens outbound connections, not just files. In one
verification run the injected command issued an HTTP GET via `curl.exe`
(ships with Windows 11) to a netcat listener in WSL2 on the same machine.
One double-click produced both effects. The listener captured:

    Connection received on 172.22.96.1 54807
    GET /<path> HTTP/1.1
    Host: 172.22.106.154:9002
    User-Agent: CVE-1-POC

`172.22.96.1` is the Windows host's `vEthernet (WSL)` address, so the
connection was initiated from the Windows machine running `launcher.exe`.
The exact command and listener setup are withheld from this public report.

### 5.4 Antivirus behaviour (observed)

* The **injection step itself** triggered nothing: the verified file-marker
  payload produced **zero** Microsoft Defender detections in the test
  window. For reference, Defender flags encoded-PowerShell variants as
  `Behavior:Win32/Execution.A!ml`.
* Microsoft Defender may false-positive the **official binaries themselves**
  (`launcher.exe`: `Behavior:Win32/Execution.A!ml`, `kyty_emulator.exe`:
  `Behavior:Win32/DefenseEvasion.A!ml`) because they are unsigned,
  unknown-reputation emulator builds. The block is hash-based, so moving the
  folder does not help; a Defender exclusion for the release folder (admin)
  does. This is unrelated to the vulnerability.
* In a real attack the injection itself is silent; defenders can only catch
  payload behaviour (e.g. `cmd.exe` spawning a downloader or shell), not the
  injection step.

A manual, script-free reproduction (edit the config value by hand, launch,
double-click the game row) was also verified with the same result.

---

## 6. Why this is Windows-only

There is a second, correctly written escaping helper used on Linux:

`src/launcher/src/mainDialog.cpp:299-302`

```cpp
static QString BashQuote(QString value) {
	value.replace('\'', "'\\''");
	return QStringLiteral("'") + value + QStringLiteral("'");
}
```

This is the standard, correct POSIX single-quote escape: every embedded `'`
is closed, escaped, and re-opened. `CreateBashScript` (`mainDialog.cpp:304-325`)
writes a script file with each argument `BashQuote`d and executes it as
`bash <file>` - never as `bash -c <string>` - so there is no second-order
parsing layer either.

Therefore CVE-1 is a **Windows-only** defect in `WinCmdQuote`; reproducing it
needs no WSL, no Linux shell, no root - the Windows release binary alone is
the whole attack surface.

---

## 7. LOLBAS / defender view

* **Process tree**: `launcher.exe` -> `cmd.exe /K ... kyty_emulator.exe ...`
  is the *normal* tree for this application, so a naive "cmd.exe spawned by
  a game app" rule will not flag it.
* **Command line**: the malicious content is buried mid-list after ~15
  benign `--flag value` pairs. Detection needs to look for a `"`+`&`
  pattern inside a value that is supposed to be a path.
* **Console window**: `CREATE_NEW_CONSOLE` opens a visible window; with
  `rem` swallowing the tail it looks like an emulator window that "failed
  to start" - unremarkable for an in-development emulator.
* **Living-off-the-land**: `cmd.exe` here can run anything - `powershell`,
  `reg`, `bitsadmin`, `certutil`, a downloader - with the emulator path as
  camouflage at the head of the command string. The attacker chooses the
  second stage.

---

## 8. Remediation

**Do not build a shell command line at all.**

1. **Primary fix (Windows)** - drop `cmd.exe` and `nativeArguments`:

   ```cpp
   process->setProgram(interpreter);
   process->setArguments(args);
   ```

   This is exactly what the `#else` branch already does
   (`mainDialog.cpp:446-448`). Qt then quotes each argument correctly for
   `CreateProcessW`, and `WinCmdQuote`/`BuildWinCmdKCommand` can be deleted.

2. If a console window that stays open is genuinely required, do not route
   user text through `/K`: pass `interpreter` + `args` as the program and
   arguments and let Qt do the quoting; never embed user-supplied text in a
   `cmd.exe /K` wrapper string.

3. **Defence in depth**: validate free-form fields at the boundary.
   `shader_log_folder`, `command_buffer_dump_folder`, `printf_output_file`
   are paths - restrict to a safe character set (letters, digits, `_-.\\/`)
   and reject `"` `&` `|` `<` `>` `^` `%` `!` in
   `Configuration::SetGameSettings` (`configuration.cpp:110-149`).

4. Do not rely on fixing `WinCmdQuote` (backslash-escaping is the wrong
   layer for cmd.exe; `""`-doubling with nested `/K` quoting is fragile).
   Prefer fix 1.

---

## 9. Repository contents

| path | purpose |
|---|---|
| `README.md` | this public vulnerability report (CVE-1) |
| `.gitignore` | keeps upstream clones and release binaries out of the repository |

Working exploit artifacts (automated PoC scripts, payload configs, probe
scripts) are **intentionally not published**. They are held privately and
are available to the maintainers under coordinated disclosure on request.
The official release zip is also not committed; download it from the release
link at the top.

---

## 10. References

* CWE-78: OS Command Injection - https://cwe.mitre.org/data/definitions/78.html
* CWE-77: Improper Neutralization of Special Elements used in a Command -
  https://cwe.mitre.org/data/definitions/77.html
* CVSS v3.1 specification (FIRST) -
  https://www.first.org/cvss/v3.1/specification-document
* CVE-1 base score, calculator view -
  https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
* Microsoft - `cmd.exe` (the `/K` switch and `&` command separator) -
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd
* Qt - `QSettings` INI format escaping -
  https://doc.qt.io/qt-6/qsettings.html#ini-format
* Qt - `QProcess` / `setNativeArguments` -
  https://doc.qt.io/qt-6/qprocess.html
* Similar class: Shellshock (CVE-2014-6271) - command injection through an
  unexpectedly parsed shell input - https://nvd.nist.gov/vuln/detail/CVE-2014-6271
* Repository audited - https://github.com/KytyPS5/KytyPS5 (commit `5a880808`)
* Release tested -
  https://github.com/KytyPS5/KytyPS5/releases/tag/KytyPS5-2026-10-08-5a88080
* PR #244 (origin of the `/K` quoting path) -
  https://github.com/KytyPS5/KytyPS5/pull/244

---

## Appendix - reproduction environment

* **OS:** Windows 11 (10.0.26300.9550), x64
* **Release:** `KytyPS5-2026-10-08-5a88080` official Windows zip,
  `launcher.exe` SHA256 `4796C3C445818B7957816DD28E1AD375C0E51757BD0DCD983EC3289AB6A9D515`
* **Verified:** dynamically end-to-end (2026-10-08, both markers + callback)
  and statically (binary literals + source)

> **Responsible disclosure:** this is a public open-source project. The
> finding has been reported to the maintainers (GitHub Security Advisory)
> and a reasonable remediation window should be allowed before public
> exploitation details are circulated further.
