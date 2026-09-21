; Installer hooks for the nexa NSIS bundle.
;
; Wired up through `bundle.windows.nsis.installerHooks` in tauri.conf.json.
;
; Background: releases ship a second binary, nexa-service.exe, which the user can register as a
; Windows service from the Settings page. While it runs it holds its own executable open, and two
; consequences follow:
;
;   * an upgrade cannot overwrite it -> NSIS pops its stock "Error opening file for writing ...
;     Abort / Retry / Ignore" dialog, none of whose three buttons actually helps (retrying against
;     a locked file cannot work, and Ignore leaves a half-updated install);
;   * neither removing the service nor killing the process is possible unprivileged, and this
;     installer is built with INSTALLMODE "currentUser", i.e. RequestExecutionLevel user.
;
; So every hook below drops the service *before* a single file is touched, asking for elevation
; when it has to, and then waits for the process to release the file. The user should never see a
; Windows service error box during an upgrade.

; LogicLib is pulled in explicitly: the generated installer may or may not already include it.
!include LogicLib.nsh

!define NEXAPIPE_SERVICE_NAME "nexa-service"
!define NEXAPIPE_SERVICE_EXE "nexa-service.exe"

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

; Stops and unregisters the service when it stands in the way. All of the work (stop, wait for the
; process to exit, force-kill it if it hangs, delete the SCM entry) has to run in ONE elevated
; process and none of it may flash a console window, hence the scratch batch file.
; On return the error flag reflects whether ${NEXAPIPE_SERVICE_EXE} is free to be overwritten.
!macro NEXAPIPE_DROP_SERVICE
  Push $0
  Push $1

  ; $0 = "something has to be dropped".
  StrCpy $0 0

  ; The service key is readable without elevation, so this alone never triggers a UAC prompt.
  ReadRegStr $1 HKLM "SYSTEM\CurrentControlSet\Services\${NEXAPIPE_SERVICE_NAME}" "ImagePath"
  ${If} $1 != ""
    StrCpy $0 1
  ${EndIf}

  ; Then ask the file itself: if it can be removed, nothing holds it, and extracting it again
  ; below restores it. This also catches a service binary launched outside the SCM.
  ClearErrors
  Delete "$INSTDIR\${NEXAPIPE_SERVICE_EXE}"
  ${If} ${Errors}
    StrCpy $0 1
  ${EndIf}

  ${If} $0 = 1
    StrCpy $1 "$TEMP\nexapipe-drop-service.cmd"
    DetailPrint "Stopping ${NEXAPIPE_SERVICE_NAME} so ${NEXAPIPE_SERVICE_EXE} can be replaced..."

    ; Reusing $0 as the file handle: the flag it held has served its purpose.
    FileOpen $0 "$1" w
    FileWrite $0 "@echo off$\r$\n"
    FileWrite $0 "sc stop ${NEXAPIPE_SERVICE_NAME} >nul 2>&1$\r$\n"
    ; The service shuts its tunnel down first, so give it a grace period before forcing it.
    ; `ping -n 2` is the one-second sleep rather than `timeout`, which refuses to run whenever
    ; its stdin is redirected - and how the elevated process is spawned is not up to us.
    FileWrite $0 "for /L %%i in (1,1,30) do ($\r$\n"
    FileWrite $0 "  tasklist /fi $\"imagename eq ${NEXAPIPE_SERVICE_EXE}$\" /nh | findstr /i /c:$\"${NEXAPIPE_SERVICE_EXE}$\" >nul || goto :stopped$\r$\n"
    FileWrite $0 "  ping -n 2 127.0.0.1 >nul 2>&1$\r$\n"
    FileWrite $0 ")$\r$\n"
    FileWrite $0 "taskkill /f /im ${NEXAPIPE_SERVICE_EXE} >nul 2>&1$\r$\n"
    FileWrite $0 "ping -n 3 127.0.0.1 >nul 2>&1$\r$\n"
    FileWrite $0 ":stopped$\r$\n"
    FileWrite $0 "sc delete ${NEXAPIPE_SERVICE_NAME} >nul 2>&1$\r$\n"
    FileClose $0

    ; "runas" raises UAC on a per-user install and is a no-op when this process already runs
    ; elevated. SW_HIDE keeps it off the user's screen.
    ExecShellWait "runas" "$SYSDIR\cmd.exe" '/c "$1"' SW_HIDE

    ; The batch file has served its purpose and only the wait below still has anything to add.
    Delete "$1"
    !insertmacro NEXAPIPE_AWAIT_UNLOCKED
  ${EndIf}

  Pop $1
  Pop $0
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro NEXAPIPE_DROP_SERVICE

  ; Last resort: something outside our control (an antivirus scan, a stray process) still holds
  ; the file. Fall back to the quiet overwrite mode so the upgrade finishes with the previous
  ; service binary left in place, instead of stopping on a dialog whose three buttons all lead
  ; nowhere.
  ${If} ${Errors}
    DetailPrint "${NEXAPIPE_SERVICE_EXE} is still in use; keeping the installed copy."
    SetOverwrite try
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Runs before the uninstaller deletes any file: while the service is running its executable is
  ; locked, and once the installation directory is gone there is nothing left for `sc` to remove.
  !insertmacro NEXAPIPE_DROP_SERVICE

  ${If} ${Errors}
    DetailPrint "${NEXAPIPE_SERVICE_EXE} is still in use; it has been left behind."
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
!macroend
