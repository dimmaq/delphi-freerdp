unit freerdp.winpr2;

interface

uses
  Winapi.Windows;

const
  LIB_WINPR2_DLL = 'winpr2.dll';

(**
 * Log Levels
 *)
  WLOG_TRACE  = 0;
  WLOG_DEBUG  = 1;
  WLOG_INFO   = 2;
  WLOG_WARN   = 3;
  WLOG_ERROR  = 4;
  WLOG_FATAL  = 5;
  WLOG_OFF    = 6;
  WLOG_LEVEL_INHERIT = $FFFF;

(**
 * Log Appenders
 *)
  WLOG_APPENDER_CONSOLE   = 0;
  WLOG_APPENDER_FILE      = 1;
  WLOG_APPENDER_BINARY    = 2;
  WLOG_APPENDER_CALLBACK  = 3;
  WLOG_APPENDER_SYSLOG    = 4;
  WLOG_APPENDER_JOURNALD  = 5;
  WLOG_APPENDER_UDP       = 6;

type
  _wLog = record

  end;
  wLog = _wLog;
  TWLog = wLog;
  PWLog = ^TwLog;

function WLog_SetLogLevel(log: PWLog; logLevel: DWORD): BOOL; cdecl;
function WLog_SetLogAppenderType(log: PWLog; logAppenderType: DWORD): BOOL; cdecl;
function WLog_GetRoot(): PWLog; cdecl;

implementation

function WLog_SetLogLevel; external LIB_WINPR2_DLL;
function WLog_GetRoot; external LIB_WINPR2_DLL;

function WLog_SetLogAppenderType; external LIB_WINPR2_DLL;

end.
