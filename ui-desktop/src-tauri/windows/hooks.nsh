; Installer hooks for the nexa NSIS bundle.
;
; Wired up through `bundle.windows.nsis.installerHooks` in tauri.conf.json.
;
; Background: releases ship a second binary, nexa-service.exe, which the user registers as a
; Windows service from the Settings page. While it runs it holds its own executable open, and two
; consequences follow:
;
;   * an upgrade cannot overwrite it -> NSIS pops its stock "Error opening file for writing ...
;     Abort / Retry / Ignore" dialog, none of whose three buttons actually helps (retrying against
;     a locked file cannot work, and Ignore leaves a half-updated install);
;   * neither stopping nor unregistering it is possible unprivileged, and this installer is built
;     with INSTALLMODE "currentUser", i.e. RequestExecutionLevel user.
;
; So every hook below drops or stops the service *before* a single file is touched, asking for
; elevation when it has to, and then waits for the process to release the file. The user should
; never see a Windows service error box during an upgrade.
;
; The two directions differ on purpose. Upgrading must not cost the user the service they had
; installed, so the installer only *stops* it and leaves the SCM entry alone (there is nothing on
; disk that needs it deleted - the binary itself is what the installer replaces), then restores
; and restarts it once the new binary is in place.
;
; Uninstalling really does drop the entry, and that path is not always taken deliberately: the
; stock maintenance page of an NSIS installer offers "Uninstall before installing" as the
; pre-selected option when it finds an older version, and the uninstaller it then runs comes
; through these very same hooks. `sc delete` takes the answer to "was a service registered here?"
; with it, so the uninstaller writes that down first (NEXAPIPE_REMEMBER_SERVICE) and the install
; that follows reads it back (NEXAPIPE_RECALL_SERVICE) instead of asking the SCM.

; LogicLib is pulled in explicitly: the generated installer may or may not already include it.
!include LogicLib.nsh

!define NEXAPIPE_SERVICE_NAME "nexa-service"
!define NEXAPIPE_SERVICE_EXE "nexa-service.exe"
!define NEXAPIPE_SERVICE_DISPLAY_NAME "Nexa Service"
; The argument the service binary is registered with. `platform::windows_impl::SERVICE_ARGUMENT`
; in the app says the same thing about the same service; the two have to stay in sync.
!define NEXAPIPE_SERVICE_ARGUMENT "--service"
; Scratch files for the elevated steps. Nothing of this survives the run.
!define NEXAPIPE_STOP_SCRIPT "$TEMP\nexapipe-stop-service.cmd"
!define NEXAPIPE_RESTORE_SCRIPT "$TEMP\nexapipe-restore-service.cmd"
!define NEXAPIPE_RESTORE_LOG "$TEMP\nexapipe-restore-service.log"

; Where the uninstaller leaves its note about the service it is about to drop, for the install
; that follows to pick up. The two product names are spelled out rather than read from
; MANUFACTURER / PRODUCTNAME, which installer.nsi defines below this include. Nothing in either
; the uninstaller or the installer removes this key, and because it keeps that manufacturer key
; non-empty not even the "delete app data" checkbox's DeleteRegKey /ifempty touches it.
!define NEXAPIPE_SERVICE_STATE_KEY "Software\nexa\nexa-service-state"

; What the pre-install hook has to give back afterwards, recorded before it stops anything:
; whether the SCM entry existed at all, and whether its own process was what held the binary open.
Var /GLOBAL NEXAPIPE_SERVICE_WAS_INSTALLED
Var /GLOBAL NEXAPIPE_SERVICE_WAS_RUNNING

; Polls the install directory until the old binary can be deleted, which is the only reliable
; proof that nothing holds it open any more. Leaves the error flag set while it is still locked.
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

; Called by the uninstaller before it drops the entry. Tells the two ways an uninstall happens
; apart without any string work: an uninstaller launched normally copies itself into the temp
; directory and runs from there, while NSIS's own `_?=` switch, which is exactly what installer.nsi
; appends when its maintenance page runs the uninstaller, keeps it in place - so the two paths are
; told apart by whether this executable is the one sitting in the installation directory.
;
;   * installer-driven - an upgrade is happening, and the install that follows has to be able to
;     get the service back, so what is registered here gets written down.
;   * genuine uninstall - someone is removing nexa from Apps & features, and it has to leave
;     nothing behind: a note would make a later reinstall resurrect a service the user removed on
;     purpose, so any stale note is cleared instead. That is also why this is called even when
;     nothing is registered; clearing the note a declined UAC prompt left behind matters just as
;     much as writing a fresh one.
!macro NEXAPIPE_REMEMBER_SERVICE
  ${If} $EXEDIR == $INSTDIR
    ${If} $NEXAPIPE_SERVICE_WAS_INSTALLED = 1
      DetailPrint "Noting that the ${NEXAPIPE_SERVICE_NAME} was registered here..."
      WriteRegStr SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}" "WasInstalled" "1"
      WriteRegStr SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}" "WasRunning" "$NEXAPIPE_SERVICE_WAS_RUNNING"
    ${EndIf}
  ${Else}
    DeleteRegKey SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}"
  ${EndIf}
!macroend

; Reads that note back, for the installer only, when the SCM itself has nothing to say. Neither
; global is ever lowered here: the entry may already have been found still registered, and a
; service that was running when it was dropped still has to be started again afterwards. The note
; itself is only cleared by NEXAPIPE_RESTORE_SERVICE, once the entry is really back.
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
; without waiting for an answer, then wait - but never for long - for the binary to be released.
;
; `sc stop` blocks until the service reports STOPPED, and how long that takes is none of this
; installer's business: anything that stays down longer than the grace period is killed anyway,
; which is exactly the outcome `sc` is waiting for. Readiness is therefore decided by the binary
; itself rather than by `sc query`, and the loop just retries the delete once a second. Ten tries
; is plenty for a graceful shutdown and puts a ceiling on a service stuck in STOP_PENDING, which
; used to hold an upgrade for minutes.
!macro NEXAPIPE_WRITE_STOP_WAIT
  FileWrite $0 'start "" /B cmd /c "sc stop ${NEXAPIPE_SERVICE_NAME} >nul 2>&1"$\r$\n'
  FileWrite $0 "for /L %%i in (1,1,10) do ($\r$\n"
  FileWrite $0 '  if not exist "$INSTDIR\${NEXAPIPE_SERVICE_EXE}" goto :stopped$\r$\n'
  FileWrite $0 '  del /f /q "$INSTDIR\${NEXAPIPE_SERVICE_EXE}" >nul 2>&1$\r$\n'
  FileWrite $0 '  if not exist "$INSTDIR\${NEXAPIPE_SERVICE_EXE}" goto :stopped$\r$\n'
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
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\${NEXAPIPE_SERVICE_NAME}" "ImagePath"
  ${If} $0 != ""
    StrCpy $NEXAPIPE_SERVICE_WAS_INSTALLED 1
  ${Else}
    ; Nothing registered right now, but an install-driven uninstall may have run moments ago and
    ; left a note about what it dropped. See NEXAPIPE_REMEMBER_SERVICE for why it keeps one.
    !insertmacro NEXAPIPE_RECALL_SERVICE
  ${EndIf}

  ; Then ask the file itself: if it can be removed, nothing holds it and there is nothing to stop,
  ; and extracting it again below restores it. A refusal means a process has it open - the service
  ; itself, or that binary launched outside the SCM, which has to go away either way.
  ClearErrors
  Delete "$INSTDIR\${NEXAPIPE_SERVICE_EXE}"
  ${If} ${Errors}
    StrCpy $NEXAPIPE_SERVICE_WAS_RUNNING 1
  ${EndIf}

  ${If} $NEXAPIPE_SERVICE_WAS_RUNNING = 1
    DetailPrint "Stopping ${NEXAPIPE_SERVICE_NAME} so ${NEXAPIPE_SERVICE_EXE} can be replaced..."

    FileOpen $0 "${NEXAPIPE_STOP_SCRIPT}" w
    FileWrite $0 "@echo off$\r$\n"
    ; Stopping is enough to free the file. The entry stays registered on purpose: deleting it here
    ; would silently uninstall the service the user had set up, and replacing the binary later in
    ; this very run is all that needs it to be down.
    !insertmacro NEXAPIPE_WRITE_STOP_WAIT
    FileClose $0

    !insertmacro NEXAPIPE_RUN_ELEVATED "${NEXAPIPE_STOP_SCRIPT}"

    ; Only the wait below still has anything to add.
    !insertmacro NEXAPIPE_AWAIT_UNLOCKED
  ${EndIf}

  Pop $1
  Pop $0
!macroend

; Puts the service back after the new binary has landed: what the Settings page does with
; `install_service`, done here so an upgrade ends the way it began. Nothing here can fail the
; installation - an upgrade that leaves the service registered but stopped is still installed, and
; the user can start it again from the same panel.
!macro NEXAPIPE_RESTORE_SERVICE
  Push $0
  Push $1

  ${If} $NEXAPIPE_SERVICE_WAS_INSTALLED = 1
    DetailPrint "Restoring ${NEXAPIPE_SERVICE_NAME}..."

    FileOpen $0 "${NEXAPIPE_RESTORE_SCRIPT}" w
    FileWrite $0 "@echo off$\r$\n"
    ; `create` fails with 1073 when an entry is already registered and `config` with 1060 when it
    ; is not, so asking first is what keeps both paths working rather than just the one expected.
    ; The binary reached with `binPath=` is quoted the way `sc` wants it: an unescaped quote in a
    ; path containing spaces is rejected with 1639. The description is cosmetic and only the app
    ; sets it, so it is not mirrored here to avoid drifting out of step with the Rust side.
    FileWrite $0 "sc.exe query ${NEXAPIPE_SERVICE_NAME} >nul 2>&1$\r$\n"
    FileWrite $0 "if not errorlevel 1 goto reconfigure$\r$\n"
    FileWrite $0 'sc.exe create ${NEXAPIPE_SERVICE_NAME} binPath= "\"$INSTDIR\${NEXAPIPE_SERVICE_EXE}\" ${NEXAPIPE_SERVICE_ARGUMENT}" start= auto DisplayName= "${NEXAPIPE_SERVICE_DISPLAY_NAME}" > "${NEXAPIPE_RESTORE_LOG}" 2>&1$\r$\n'
    FileWrite $0 "goto registered$\r$\n"
    FileWrite $0 ":reconfigure$\r$\n"
    ; The install directory can move between versions, and the entry then still points at a path
    ; that no longer exists.
    FileWrite $0 'sc.exe config ${NEXAPIPE_SERVICE_NAME} binPath= "\"$INSTDIR\${NEXAPIPE_SERVICE_EXE}\" ${NEXAPIPE_SERVICE_ARGUMENT}" start= auto > "${NEXAPIPE_RESTORE_LOG}" 2>&1$\r$\n'
    FileWrite $0 ":registered$\r$\n"
    ${If} $NEXAPIPE_SERVICE_WAS_RUNNING = 1
      ; Only ever started again when it was running before the upgrade: a service the user had
      ; stopped deliberately has to stay stopped.
      FileWrite $0 "sc.exe start ${NEXAPIPE_SERVICE_NAME} >nul 2>&1$\r$\n"
    ${EndIf}
    FileWrite $0 "exit /b 0$\r$\n"
    FileClose $0

    !insertmacro NEXAPIPE_RUN_ELEVATED "${NEXAPIPE_RESTORE_SCRIPT}"

    ; `cmd.exe` wrote `sc.exe`'s answer into the log, which is the only way to learn anything from
    ; an elevated child: nothing comes back through "runas", and DetailPrint is where whoever has
    ; to debug this will look.
    ClearErrors
    FileOpen $0 "${NEXAPIPE_RESTORE_LOG}" r
    ${IfNot} ${Errors}
      FileRead $0 $1
      ${If} $1 != ""
        DetailPrint "${NEXAPIPE_SERVICE_NAME}: $1"
      ${EndIf}
      FileClose $0
      Delete "${NEXAPIPE_RESTORE_LOG}"
    ${EndIf}

    ; Forget the note only once the entry is really back. A declined UAC prompt keeps it for the
    ; next attempt instead of costing the user their service.
    ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\${NEXAPIPE_SERVICE_NAME}" "ImagePath"
    ${If} $0 != ""
      DeleteRegKey SHCTX "${NEXAPIPE_SERVICE_STATE_KEY}"
    ${EndIf}
  ${EndIf}

  Pop $1
  Pop $0
!macroend

; Stops and unregisters the service when it stands in the way, for the uninstaller only: once the
; installation directory is gone there is nothing left for `sc` to remove.
!macro NEXAPIPE_DROP_SERVICE
  Push $0
  Push $1

  StrCpy $NEXAPIPE_SERVICE_WAS_INSTALLED 0
  StrCpy $NEXAPIPE_SERVICE_WAS_RUNNING 0

  ; The service key is readable without elevation, so this alone never triggers a UAC prompt.
  ReadRegStr $1 HKLM "SYSTEM\CurrentControlSet\Services\${NEXAPIPE_SERVICE_NAME}" "ImagePath"
  ${If} $1 != ""
    StrCpy $NEXAPIPE_SERVICE_WAS_INSTALLED 1
  ${EndIf}

  ; Then ask the file itself: if it can be removed, nothing holds it, and extracting it again
  ; below restores it. This also catches a service binary launched outside the SCM.
  ClearErrors
  Delete "$INSTDIR\${NEXAPIPE_SERVICE_EXE}"
  ${If} ${Errors}
    StrCpy $NEXAPIPE_SERVICE_WAS_RUNNING 1
  ${EndIf}

  ; Note what is registered here before it goes - or make sure nothing is left behind. The macro
  ; itself tells an installer-driven uninstall, which has to be followed by getting the service
  ; back, from a genuine one, which must not leave anything that could resurrect it later.
  !insertmacro NEXAPIPE_REMEMBER_SERVICE

  ${If} $NEXAPIPE_SERVICE_WAS_INSTALLED = 1
  ${OrIf} $NEXAPIPE_SERVICE_WAS_RUNNING = 1
    DetailPrint "Stopping ${NEXAPIPE_SERVICE_NAME} so it can be unregistered..."

    FileOpen $0 "${NEXAPIPE_STOP_SCRIPT}" w
    FileWrite $0 "@echo off$\r$\n"
    ${If} $NEXAPIPE_SERVICE_WAS_RUNNING = 1
      !insertmacro NEXAPIPE_WRITE_STOP_WAIT
    ${EndIf}
    ${If} $NEXAPIPE_SERVICE_WAS_INSTALLED = 1
      FileWrite $0 "sc delete ${NEXAPIPE_SERVICE_NAME} >nul 2>&1$\r$\n"
    ${EndIf}
    FileClose $0

    !insertmacro NEXAPIPE_RUN_ELEVATED "${NEXAPIPE_STOP_SCRIPT}"

    !insertmacro NEXAPIPE_AWAIT_UNLOCKED
  ${EndIf}

  Pop $1
  Pop $0
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
  ; locked, and once the installation directory is gone there is nothing left for `sc` to remove.
  !insertmacro NEXAPIPE_DROP_SERVICE

  ${If} ${Errors}
    DetailPrint "${NEXAPIPE_SERVICE_EXE} is still in use; it has been left behind."
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
!macroend
