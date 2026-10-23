; Installer hooks for the nexa NSIS bundle.
;
; Wired up through `bundle.windows.nsis.installerHooks` in tauri.conf.json.
;
; Background: releases ship a second binary, nexa-service.exe, which the user registers as a
; Windows service from the Settings page. The service runs as LocalSystem, so the binary the
; service control manager starts must not be writable by the ordinary user who installed the
; app: a replaced service binary is a program of the user's choosing running as SYSTEM.
;
; The app's own registration therefore copies that binary into a system-wide directory
; (C:\Program Files\Nexa\Service) and points the entry at the copy - see `system_service_dir`
; and `system_service_binary` in src/service/platform/mod.rs. This installer does not write the
; control manager's `binPath` at all: where that file lives is the app's decision, the app makes
; it while it is elevated, and a second copy of the rule written down here would drift from it -
; and would be a copy of it written by a program that runs as the user.
;
; What is left for the installer is what the app cannot do on its own:
;
;   * the service holds the *system-wide* copy of the binary open while it runs, so the file
;     this installer replaces - the copy in the app's own directory - is not the one that is
;     running, and the installer has to ask the control manager whether the service is up
;     instead of guessing it from a file that is not locked any more;
;   * stopping and starting it needs administrator rights, and this installer is built with
;     INSTALLMODE "currentUser", i.e. RequestExecutionLevel user, so those steps are written
;     into a batch file and run through a UAC prompt;
;   * the user should never see a Windows service error box during an upgrade.
;
; The two directions differ on purpose. Upgrading must not cost the user the service they had
; installed, so the installer only *stops* it and leaves the entry alone - the entry points at
; the system-wide copy, which this upgrade does not touch - and then starts it again once the
; new files are in place. The app re-registers the service when the user asks it to from the
; Settings page, and that is what puts a new build of the service binary under Program Files.
;
; Uninstalling really does drop the entry, and that path is not always taken deliberately: the
; stock maintenance page of an NSIS installer offers "Uninstall before installing" as the
; pre-selected option when it finds an older version, and the uninstaller it then runs comes
; through these very same hooks. The two are told apart by where the uninstaller runs from, so
; the uninstaller that is part of an upgrade leaves the entry alone - the install that follows
; cannot recreate it, because only the app knows where the binary it points at lives - while a
; genuine uninstall drops the entry and takes the system-wide copy with it.

; LogicLib is pulled in explicitly: the generated installer may or may not already include it.
!include LogicLib.nsh

!define NEXAPIPE_SERVICE_NAME "nexa-service"
!define NEXAPIPE_SERVICE_EXE "nexa-service.exe"
; Where the control manager keeps the entry. Readable without elevation, which is what makes
; it useful here: the installer can ask what is registered without asking the user for
; administrator rights first.
!define NEXAPIPE_SERVICE_KEY "SYSTEM\CurrentControlSet\Services\${NEXAPIPE_SERVICE_NAME}"
; The argument the service binary is registered with. `platform::windows_impl::SERVICE_ARGUMENT`
; in the app says the same thing about the same service; the two have to stay in sync.
!define NEXAPIPE_SERVICE_ARGUMENT "--service"
; Where the app's own registration writes down the path of the system-wide copy of the service
; binary - the one the control manager is pointed at. The installer reads it instead of
; deriving the path itself: where the app puts that file is the app's decision
; (`system_service_dir` in src/service/platform/mod.rs), and a second copy of the rule written
; down here would drift from it. The companion change on the Rust side writes this value when
; the service is registered and removes it when the service is uninstalled.
!define NEXAPIPE_SYSTEM_BINARY_KEY "Software\nexa\nexa-service-system"
!define NEXAPIPE_SYSTEM_BINARY_VALUE "Binary"
; Scratch files for the elevated steps. Nothing of this survives the run.
;
; Their names are drawn at run time rather than fixed. A batch file written to a predictable
; path in a per-user temporary directory is a file another account on the same machine can
; create first, and this installer then runs whatever is there with administrator rights:
; `FileOpen ... w` truncates it and overwrites it, so planting the file is enough to have the
; installer's own UAC prompt execute commands the planting account chose. `GetTempFileName`
; asks the OS for a name it has already reserved for this process, so nothing can be sitting
; there first.
;
; `Var` rather than `!define`: these are per-run values, and a name picked when the installer
; was built is no better than one written down here.
Var /GLOBAL NEXAPIPE_STOP_SCRIPT
Var /GLOBAL NEXAPIPE_RESTORE_SCRIPT
Var /GLOBAL NEXAPIPE_RESTORE_LOG
Var /GLOBAL NEXAPIPE_QUERY_SCRIPT
Var /GLOBAL NEXAPIPE_QUERY_LOG

; Puts a fresh OS-chosen path ending in `ext` in `name`. `GetTempFileName` creates an empty
; `.tmp` file, which is what reserves the name, and the file is then renamed to `ext`: `cmd /c`
; runs a file as a batch script only for `.cmd` / `.bat`, and a `.tmp` goes to whatever the file
; association says, usually nothing. `Rename` refuses an existing destination, so a file planted
; at the renamed path makes the reservation fail rather than get reused. The caller overwrites
; the reserved file with `FileOpen`. A reservation that could not be made leaves an empty string,
; and every use below reads one of these only after checking it is not empty — so the elevated
; step is skipped rather than run against a path nobody reserved.
;
; No labels, for the reason the wait macro below gives: this is inserted more than once.
!macro NEXAPIPE_TEMP_FILE name ext
  Push $0
  ClearErrors
  GetTempFileName $0 "$TEMP"
  ${If} ${Errors}
  ${OrIf} $0 == ""
    StrCpy $0 ""
  ${Else}
    ClearErrors
    Rename $0 "$0${ext}"
    ${If} ${Errors}
      Delete $0
      StrCpy $0 ""
    ${Else}
      StrCpy $0 "$0${ext}"
    ${EndIf}
  ${EndIf}
  ${If} $0 == ""
    DetailPrint "Could not reserve a temporary file name; skipping the elevated step."
  ${EndIf}
  StrCpy ${name} $0
  Pop $0
!macroend

; Where the uninstaller leaves its note about the service it is about to drop, for the install
; that follows to pick up. The two product names are spelled out rather than read from
; MANUFACTURER / PRODUCTNAME, which installer.nsi defines below this include. Nothing in either
; the uninstaller or the installer removes this key, and because it keeps that manufacturer key
; non-empty not even the "delete app data" checkbox's DeleteRegKey /ifempty touches it.
!define NEXAPIPE_SERVICE_STATE_KEY "Software\nexa\nexa-service-state"

; What the pre-install hook has to give back afterwards, recorded before it stops anything:
; whether the SCM entry existed at all, and whether the service was running.
Var /GLOBAL NEXAPIPE_SERVICE_WAS_INSTALLED
Var /GLOBAL NEXAPIPE_SERVICE_WAS_RUNNING
; Whether the entry is still pointed at the copy of the binary in this directory, which the
; ordinary user can replace - see NEXAPIPE_ENTRY_IS_USER_WRITABLE.
Var /GLOBAL NEXAPIPE_SERVICE_IS_USER_WRITABLE
; Where the app's registration put the system-wide copy of the service binary, or the empty
; string when it did not register one - see NEXAPIPE_SYSTEM_BINARY_KEY.
Var /GLOBAL NEXAPIPE_SYSTEM_BINARY
; Whether the uninstaller that is running is one an installer started, or a genuine one.
Var /GLOBAL NEXAPIPE_UNINSTALL_IS_UPGRADE

; Polls the install directory until the old binary can be deleted, which is the only reliable
; proof that nothing holds it open any more. Leaves the error flag set while it is still locked.
; The service is not what holds it: it runs the system-wide copy of the binary, so this is
; about a copy that was launched outside the control manager's reach.
; No labels: this macro is inserted twice and NSIS labels are global.
!macro NEXAPIPE_AWAIT_UNLOCKED
  Push $0
  StrCpy $0 0
  ${Do}
    ClearErrors
    Delete "$INSTDIR\${NEXAPIPE_SERVICE_EXE}"
    ${IfNot} ${Errors}
      ${Break}
    ${EndIf}
    Sleep 1000
    IntOp $0 $0 + 1
  ${LoopUntil} $0 >= 15
  Pop $0
!macroend

; Asks the control manager whether the service is running, and raises
; $NEXAPIPE_SERVICE_WAS_RUNNING when it is. The flag is only ever raised here: what the
; answer is when there is none is the caller's business.
;
; `sc query` is the honest question. The service runs the system-wide copy of the binary, so
; whether the copy in this directory can be deleted says nothing about it any more - that
; file is not the one the control manager opens. The query needs no administrator rights, so
; asking it never puts a UAC prompt in front of the user.
;
; `sc` prints the state on stdout, which the installer cannot see for itself, so the question
; is asked from a batch file that leaves the answer in a log - the same "the only way to learn
; anything from a child process" arrangement the restore uses.
!macro NEXAPIPE_QUERY_STATE
  Push $0
  Push $1

  !insertmacro NEXAPIPE_TEMP_FILE $NEXAPIPE_QUERY_SCRIPT ".cmd"
  !insertmacro NEXAPIPE_TEMP_FILE $NEXAPIPE_QUERY_LOG ".log"

  ${If} $NEXAPIPE_QUERY_SCRIPT != ""
  ${AndIf} $NEXAPIPE_QUERY_LOG != ""
    FileOpen $0 $NEXAPIPE_QUERY_SCRIPT w
    FileWrite $0 "@echo off$\r$\n"
    ; The word is written over the log, so that the installer reads one word instead of
    ; parsing `sc`'s output. It is only written when the service is running; anything else
    ; leaves the log with what `sc` said, which is not that word.
    FileWrite $0 'sc.exe query ${NEXAPIPE_SERVICE_NAME} > "$NEXAPIPE_QUERY_LOG" 2>&1$\r$\n'
    FileWrite $0 'find /i "RUNNING" "$NEXAPIPE_QUERY_LOG" >nul && echo RUNNING> "$NEXAPIPE_QUERY_LOG"$\r$\n'
    FileClose $0

    ; No elevation: `sc query` reads the state of any service without administrator rights,
    ; and a UAC prompt in front of every upgrade would be a poor trade for the answer.
    ExecShellWait "open" "$SYSDIR\cmd.exe" '/c "$NEXAPIPE_QUERY_SCRIPT"' SW_HIDE

    ClearErrors
    FileOpen $0 $NEXAPIPE_QUERY_LOG r
    ${IfNot} ${Errors}
      ; FileRead stops at the line break, so the word comes back without it.
      FileRead $0 $1
      FileClose $0
      ${If} $1 == "RUNNING"
        StrCpy $NEXAPIPE_SERVICE_WAS_RUNNING 1
      ${EndIf}
    ${EndIf}
  ${EndIf}

  ; Neither scratch file outlives the question.
  ${If} $NEXAPIPE_QUERY_SCRIPT != ""
    Delete $NEXAPIPE_QUERY_SCRIPT
  ${EndIf}
  ${If} $NEXAPIPE_QUERY_LOG != ""
    Delete $NEXAPIPE_QUERY_LOG
  ${EndIf}

  Pop $1
  Pop $0
!macroend

; Whether the control manager is pointed at the copy of the service binary that lives in this
; directory, and leaves the answer in `out` (1 or 0). That copy belongs to the ordinary user,
; and the service runs as SYSTEM, so an entry pointing at it is an escalation rather than a
; service - and the installer must not start it.
;
; Two shapes have been written there over the years: by an earlier version of this installer,
; and by an earlier version of the app, which looked for the binary in the resources directory
; first. The entry is compared whole, because that is what the control manager stores: the
; executable in quotes, followed by the argument the service is registered with.
!macro NEXAPIPE_ENTRY_IS_USER_WRITABLE out
  Push $0
  Push $1

  StrCpy ${out} 0
  ReadRegStr $0 HKLM "${NEXAPIPE_SERVICE_KEY}" "ImagePath"
  ${If} $0 != ""
    StrCpy $1 '"$INSTDIR\${NEXAPIPE_SERVICE_EXE}" ${NEXAPIPE_SERVICE_ARGUMENT}'
    ${If} $0 == $1
      StrCpy ${out} 1
    ${EndIf}
    StrCpy $1 '"$INSTDIR\resources\${NEXAPIPE_SERVICE_EXE}" ${NEXAPIPE_SERVICE_ARGUMENT}'
    ${If} $0 == $1
      StrCpy ${out} 1
    ${EndIf}
  ${EndIf}

  Pop $1
  Pop $0
!macroend

; Called by the uninstaller before it drops the entry. Tells the two ways an uninstall happens
; apart without any string work: an uninstaller launched normally copies itself into the temp
; directory and runs from there, while NSIS's own `_?=` switch, which is exactly what installer.nsi
; appends when its maintenance page runs the uninstaller, keeps it in place - so the two paths are
; told apart by whether this executable is the one sitting in the installation directory.
;
;   * installer-driven - an upgrade is happening, and the install that follows has to be able to
;     get the service back, so what is registered here gets written down. The entry itself is
;     left alone: the install that follows cannot recreate it, because only the app knows
;     where the binary it points at lives, and that binary is still there.
;   * genuine uninstall - someone is removing nexa from Apps & features, and it has to leave
;     nothing behind: a note would make a later reinstall resurrect a service the user removed on
;     purpose, so any stale note is cleared instead. That is also why this is called even when
;     nothing is registered; clearing the note a declined UAC prompt left behind matters just as
;     much as writing a fresh one.
!macro NEXAPIPE_REMEMBER_SERVICE
  ${If} $EXEDIR == $INSTDIR
    StrCpy $NEXAPIPE_UNINSTALL_IS_UPGRADE 1
    ${If} $NEXAPIPE_SERVICE_WAS_INSTALLED = 1
      DetailPrint "Noting that the ${NEXAPIPE_SERVICE_NAME} was registered here..."
      WriteRegStr SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}" "WasInstalled" "1"
      WriteRegStr SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}" "WasRunning" "$NEXAPIPE_SERVICE_WAS_RUNNING"
    ${EndIf}
  ${Else}
    StrCpy $NEXAPIPE_UNINSTALL_IS_UPGRADE 0
    DeleteRegKey SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}"
  ${EndIf}
!macroend

; Reads that note back, for the installer only, when the SCM itself has nothing to say. Neither
; global is ever lowered here: the entry may already have been found still registered, and a
; service that was running when it was dropped still has to be started again afterwards. The note
; itself is only cleared by NEXAPIPE_RESTORE_SERVICE, once the entry is really back.
;
; The note is read even when the entry is still there. An uninstall that is part of an upgrade
; leaves the entry alone - the install that follows cannot recreate it - so the note is the only
; thing that still says the service was running before the upgrade.
!macro NEXAPIPE_RECALL_SERVICE
  Push $0
  ReadRegStr $0 SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}" "WasInstalled"
  ${If} $0 == "1"
    StrCpy $NEXAPIPE_SERVICE_WAS_INSTALLED 1
    ReadRegStr $0 SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}" "WasRunning"
    ${IfThen} $0 == "1" ${|} StrCpy $NEXAPIPE_SERVICE_WAS_RUNNING 1 ${|}
    DetailPrint "${NEXAPIPE_SERVICE_NAME} was registered here before; putting it back."
  ${EndIf}
  Pop $0
!macroend

; Runs `script` once through a single UAC prompt and removes it afterwards. "runas" raises UAC on
; a per-user install and is a no-op when this process already runs elevated; SW_HIDE keeps the
; console off the user's screen.
!macro NEXAPIPE_RUN_ELEVATED script
  ExecShellWait "runas" "$SYSDIR\cmd.exe" '/c "${script}"' SW_HIDE
  Delete "${script}"
!macroend

; Writes into the batch file currently open on $0 the part both stop paths share: ask for a stop
; without waiting for an answer, then wait - but never for long - for the service to be down.
;
; `sc stop` blocks until the service reports STOPPED, and how long that takes is none of this
; installer's business: anything that stays down longer than the grace period is killed anyway,
; which is exactly the outcome `sc` is waiting for. Readiness is therefore decided by the
; control manager itself - `sc query` says which state the service is in - and not by whether
; a file in this directory can be deleted, which says nothing about a service that runs the
; system-wide copy of the binary. The loop just asks once a second. Ten tries is plenty for a
; graceful shutdown and puts a ceiling on a service stuck in STOP_PENDING, which used to hold
; an upgrade for minutes.
!macro NEXAPIPE_WRITE_STOP_WAIT
  FileWrite $0 'start "" /B cmd /c "sc stop ${NEXAPIPE_SERVICE_NAME} >nul 2>&1"$\r$\n'
  FileWrite $0 "for /L %%i in (1,1,10) do ($\r$\n"
  FileWrite $0 '  sc.exe query ${NEXAPIPE_SERVICE_NAME} 2>&1 | find /i "STOPPED" >nul && goto :stopped$\r$\n'
  FileWrite $0 "  ping -n 2 127.0.0.1 >nul 2>&1$\r$\n"
  FileWrite $0 ")$\r$\n"
  FileWrite $0 "taskkill /f /im ${NEXAPIPE_SERVICE_EXE} >nul 2>&1$\r$\n"
  FileWrite $0 "ping -n 2 127.0.0.1 >nul 2>&1$\r$\n"
  FileWrite $0 ":stopped$\r$\n"
!macroend

; Stops the service when it stands in the way of replacing its binary, without touching the SCM
; entry, and records what has to be restored once the new files are down. All of the work (stop,
; wait for the process to exit, force-kill it if it hangs) has to run in ONE elevated process and
; none of it may flash a console window, hence the scratch batch file.
!macro NEXAPIPE_STOP_SERVICE
  Push $0
  Push $1

  StrCpy $NEXAPIPE_SERVICE_WAS_INSTALLED 0
  StrCpy $NEXAPIPE_SERVICE_WAS_RUNNING 0

  ; The service key is readable without elevation, so this alone never triggers a UAC prompt.
  ReadRegStr $0 HKLM "${NEXAPIPE_SERVICE_KEY}" "ImagePath"
  ${If} $0 != ""
    StrCpy $NEXAPIPE_SERVICE_WAS_INSTALLED 1
  ${EndIf}

  ; The note an install-driven uninstall left behind is read in any case: the entry is still
  ; there in that case, but the note is the only thing that says the service was running
  ; before the upgrade. See NEXAPIPE_RECALL_SERVICE for why it keeps one.
  !insertmacro NEXAPIPE_RECALL_SERVICE

  ; Then ask the control manager, which is the only one that knows: the service runs the
  ; system-wide copy of the binary, so whether the copy in this directory can be deleted says
  ; nothing about whether the service is up.
  !insertmacro NEXAPIPE_QUERY_STATE

  ${If} $NEXAPIPE_SERVICE_WAS_RUNNING = 1
    DetailPrint "Stopping ${NEXAPIPE_SERVICE_NAME} so it can be started again afterwards..."

    ; Reserved now, opened below: the name has to exist before the script is written into it,
    ; or there is a window in which another account creates the file first.
    !insertmacro NEXAPIPE_TEMP_FILE $NEXAPIPE_STOP_SCRIPT ".cmd"
    ${If} $NEXAPIPE_STOP_SCRIPT != ""
      FileOpen $0 $NEXAPIPE_STOP_SCRIPT w
      FileWrite $0 "@echo off$\r$\n"
      ; Stopping is enough to leave the machine the way the upgrade expects it. The entry stays
      ; registered on purpose: deleting it here would silently uninstall the service the user
      ; had set up, and the entry is what points at the binary the control manager may run.
      !insertmacro NEXAPIPE_WRITE_STOP_WAIT
      FileClose $0

      !insertmacro NEXAPIPE_RUN_ELEVATED $NEXAPIPE_STOP_SCRIPT
    ${EndIf}
  ${EndIf}

  ; The wait below still has anything to add: the copy in this directory can be held by a
  ; process the control manager knows nothing about, and the installer has to be able to
  ; replace it.
  !insertmacro NEXAPIPE_AWAIT_UNLOCKED

  Pop $1
  Pop $0
!macroend

; Starts the service again after the new binary has landed, so an upgrade ends the way it
; began. Nothing here can fail the installation - an upgrade that leaves the service registered
; but stopped is still installed, and the user can start it again from the same panel.
;
; What this does *not* do is write the control manager's `binPath`. The entry points at the
; system-wide copy of the binary - the one under Program Files that the ordinary user cannot
; replace, and that the app's own elevated registration put there - and this installer has no
; business moving it. Writing the path of a file in this directory instead is what handed the
; service to whoever can write that directory; see the comment at the top of this file.
;
; The entry that an earlier version of this installer wrote is a special case: it points at a
; file the user can replace, and the service runs it as SYSTEM. The installer does not start
; such an entry, and says what has to be done about it.
!macro NEXAPIPE_RESTORE_SERVICE
  Push $0
  Push $1

  ${If} $NEXAPIPE_SERVICE_WAS_INSTALLED = 1
    !insertmacro NEXAPIPE_ENTRY_IS_USER_WRITABLE $NEXAPIPE_SERVICE_IS_USER_WRITABLE

    ${If} $NEXAPIPE_SERVICE_IS_USER_WRITABLE = 1
      ; The entry still points at the copy of the binary in this directory, which the ordinary
      ; user can replace and the service would run as SYSTEM. The app's registration is what
      ; moves it to the copy under Program Files, and it needs the user's own consent to run
      ; elevated, so the installer does not start this one and says what to do about it.
      DetailPrint "The ${NEXAPIPE_SERVICE_NAME} still points at ${NEXAPIPE_SERVICE_EXE} in this directory; register it again from the Settings page to move it."
    ${EndIf}

    ${If} $NEXAPIPE_SERVICE_WAS_RUNNING = 1
    ${AndIf} $NEXAPIPE_SERVICE_IS_USER_WRITABLE = 0
      DetailPrint "Starting ${NEXAPIPE_SERVICE_NAME} again..."

      ; Both names reserved before either is written: the log path is baked into the script text
      ; below, so it has to exist before that text is written, and both are handed out by the OS
      ; rather than named here. Both are required, too: a script redirecting into `""` fails the
      ; redirection, and `cmd` then never runs the `sc.exe` line it was attached to.
      !insertmacro NEXAPIPE_TEMP_FILE $NEXAPIPE_RESTORE_SCRIPT ".cmd"
      !insertmacro NEXAPIPE_TEMP_FILE $NEXAPIPE_RESTORE_LOG ".log"

      ${If} $NEXAPIPE_RESTORE_SCRIPT != ""
      ${AndIf} $NEXAPIPE_RESTORE_LOG != ""
        FileOpen $0 $NEXAPIPE_RESTORE_SCRIPT w
        FileWrite $0 "@echo off$\r$\n"
        ; The entry is left exactly as the app registered it, so this starts the binary the
        ; control manager has always started: the system-wide copy, which the user cannot
        ; replace.
        FileWrite $0 'sc.exe start ${NEXAPIPE_SERVICE_NAME} > "$NEXAPIPE_RESTORE_LOG" 2>&1$\r$\n'
        FileWrite $0 "exit /b 0$\r$\n"
        FileClose $0

        !insertmacro NEXAPIPE_RUN_ELEVATED $NEXAPIPE_RESTORE_SCRIPT

        ; `cmd.exe` wrote `sc.exe`'s answer into the log, which is the only way to learn anything
        ; from an elevated child: nothing comes back through "runas", and DetailPrint is where
        ; whoever has to debug this will look.
        ClearErrors
        FileOpen $0 "$NEXAPIPE_RESTORE_LOG" r
        ${IfNot} ${Errors}
          FileRead $0 $1
          ${If} $1 != ""
            DetailPrint "${NEXAPIPE_SERVICE_NAME}: $1"
          ${EndIf}
          FileClose $0
          Delete "$NEXAPIPE_RESTORE_LOG"
        ${EndIf}
      ${Else}
        ; Whichever of the two did get reserved is not going to be used.
        ${If} $NEXAPIPE_RESTORE_SCRIPT != ""
          Delete $NEXAPIPE_RESTORE_SCRIPT
        ${EndIf}
        ${If} $NEXAPIPE_RESTORE_LOG != ""
          Delete $NEXAPIPE_RESTORE_LOG
        ${EndIf}
      ${EndIf}
    ${EndIf}

    ; Forget the note only once the entry is really back. A declined UAC prompt keeps it for the
    ; next attempt instead of costing the user their service.
    ReadRegStr $0 HKLM "${NEXAPIPE_SERVICE_KEY}" "ImagePath"
    ${If} $0 != ""
      DeleteRegKey SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}"
    ${EndIf}
  ${EndIf}

  Pop $1
  Pop $0
!macroend

; Stops and unregisters the service when it stands in the way, for the uninstaller only: once the
; installation directory is gone there is nothing left for `sc` to remove.
;
; The two directions are told apart, because they cannot both do the same thing. An uninstall
; that is part of an upgrade leaves the entry alone: the install that follows cannot recreate
; it, because only the app knows where the binary it points at lives, and the service is
; expected to be there when the upgrade is done. A genuine uninstall drops the entry and takes
; the system-wide copy of the binary with it - neither is the user's to keep.
!macro NEXAPIPE_DROP_SERVICE
  Push $0
  Push $1
  Push $2

  StrCpy $NEXAPIPE_SERVICE_WAS_INSTALLED 0
  StrCpy $NEXAPIPE_SERVICE_WAS_RUNNING 0
  StrCpy $NEXAPIPE_SYSTEM_BINARY ""

  ; The service key is readable without elevation, so this alone never triggers a UAC prompt.
  ReadRegStr $1 HKLM "${NEXAPIPE_SERVICE_KEY}" "ImagePath"
  ${If} $1 != ""
    StrCpy $NEXAPIPE_SERVICE_WAS_INSTALLED 1
  ${EndIf}

  ; Where the app's registration put the copy of the binary that the control manager runs.
  ; It is read even when nothing is registered any more: the copy is not the user's to keep,
  ; and an entry that is gone does not make the file that was behind it any less theirs.
  ReadRegStr $2 HKLM "${NEXAPIPE_SYSTEM_BINARY_KEY}" "${NEXAPIPE_SYSTEM_BINARY_VALUE}"
  ${If} $2 != ""
    StrCpy $NEXAPIPE_SYSTEM_BINARY $2
  ${EndIf}

  ; Then ask the control manager, which is the only one that knows whether the service is up:
  ; it runs the system-wide copy of the binary, so whether the copy in this directory can be
  ; deleted says nothing about it any more.
  !insertmacro NEXAPIPE_QUERY_STATE

  ; Note what is registered here before it goes - or make sure nothing is left behind. The macro
  ; itself tells an installer-driven uninstall, which has to be followed by getting the service
  ; back, from a genuine one, which must not leave anything that could resurrect it later.
  !insertmacro NEXAPIPE_REMEMBER_SERVICE

  ${If} $NEXAPIPE_SERVICE_WAS_INSTALLED = 1
  ${OrIf} $NEXAPIPE_SERVICE_WAS_RUNNING = 1
  ${OrIf} $NEXAPIPE_SYSTEM_BINARY != ""
    DetailPrint "Stopping ${NEXAPIPE_SERVICE_NAME} so it can be unregistered..."

    ; Reserved before it is written into, for the reason the macro gives.
    !insertmacro NEXAPIPE_TEMP_FILE $NEXAPIPE_STOP_SCRIPT ".cmd"
    ${If} $NEXAPIPE_STOP_SCRIPT != ""
      FileOpen $0 $NEXAPIPE_STOP_SCRIPT w
      FileWrite $0 "@echo off$\r$\n"
      ${If} $NEXAPIPE_SERVICE_WAS_RUNNING = 1
        !insertmacro NEXAPIPE_WRITE_STOP_WAIT
      ${EndIf}
      ${If} $NEXAPIPE_UNINSTALL_IS_UPGRADE = 0
        ${If} $NEXAPIPE_SERVICE_WAS_INSTALLED = 1
          ; The entry goes before the file it points at: an entry left behind and pointing at a
          ; file that has just been deleted is a service that cannot start.
          FileWrite $0 "sc.exe delete ${NEXAPIPE_SERVICE_NAME} >nul 2>&1$\r$\n"
        ${EndIf}
        !insertmacro NEXAPIPE_WRITE_REMOVE_SYSTEM_COPY
      ${EndIf}
      FileClose $0

      !insertmacro NEXAPIPE_RUN_ELEVATED $NEXAPIPE_STOP_SCRIPT
    ${EndIf}

    !insertmacro NEXAPIPE_AWAIT_UNLOCKED
  ${EndIf}

  Pop $2
  Pop $1
  Pop $0
!macroend

; Writes into the batch file currently open on $0 the removal of the system-wide copy of the
; service binary, for the uninstaller only.
;
; The path is the one the app's own registration wrote down, not one written here: where the
; app puts that file is the app's decision (`system_service_dir` in
; src/service/platform/mod.rs), and a copy of the rule in this file would drift from it. A copy
; that is not there to be found - because the service was never registered by this build of the
; app - is the app's to remove: its own uninstall does it, and says so when it cannot.
!macro NEXAPIPE_WRITE_REMOVE_SYSTEM_COPY
  ${If} $NEXAPIPE_SYSTEM_BINARY != ""
    FileWrite $0 'del /f /q "$NEXAPIPE_SYSTEM_BINARY" >nul 2>&1$\r$\n'
    ; The directory is only removed when it is empty: anything else in it belongs to somebody
    ; else, and leaving it behind is harmless.
    FileWrite $0 'for %%d in ("$NEXAPIPE_SYSTEM_BINARY") do rmdir "%%~dp" >nul 2>&1$\r$\n'
  ${Else}
    DetailPrint "The ${NEXAPIPE_SERVICE_NAME} was not registered by this build; leaving its copy under Program Files to the app."
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro NEXAPIPE_STOP_SERVICE

  ; Last resort: something outside our control (an antivirus scan, a stray process) still holds
  ; the file. Fall back to the quiet overwrite mode so the upgrade finishes with the previous
  ; service binary left in place, instead of stopping on a dialog whose three buttons all lead
  ; nowhere.
  ${If} ${Errors}
    DetailPrint "${NEXAPIPE_SERVICE_EXE} is still in use; keeping the installed copy."
    SetOverwrite try
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro NEXAPIPE_RESTORE_SERVICE
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Runs before the uninstaller deletes any file: while the service is running its executable is
  ; locked - the system-wide copy, not the one in this directory - and once the installation
  ; directory is gone there is nothing left for `sc` to remove.
  !insertmacro NEXAPIPE_DROP_SERVICE

  ${If} ${Errors}
    DetailPrint "${NEXAPIPE_SERVICE_EXE} is still in use; it has been left behind."
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
!macroend
