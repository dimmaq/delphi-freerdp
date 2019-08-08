unit freerdp.client;

interface

uses
  System.SysUtils, Winapi.Windows,
  //
  freerdp.freerdp2;

const
  RDP_CLIENT_INTERFACE_VERSION = 1;
  RDP_CLIENT_ENTRY_POINT_NAME = 'RdpClientEntry';


type
  tf_context = record
    context: TRdpContext;

    (* Channels *)
//    RdpeiClientContext* rdpei;
//    RdpgfxClientContext* gfx;
//    EncomspClientContext* encomsp;
  end;
  tfContext = tf_context;

function freerdp_client_context_new(const pEntryPoints: PRdpClientEntryPoints): PRdpContext;

procedure freerdp_client_context_free(context: PRdpContext);
function freerdp_client_start(context: PRdpContext): Integer;
function freerdp_client_stop(context: PRdpContext): Integer;

implementation

function freerdp_client_context_new(const pEntryPoints: PRdpClientEntryPoints): PRdpContext;
label
  out_fail, out_fail2;
var
	instance: PFreerdp;
	context: PRdpContext;
begin
	if pEntryPoints = nil then
		Exit(nil);

	IfCall(pEntryPoints.GlobalInit);
	instance := freerdp_new();

	if instance = nil then
		Exit(nil);

	instance.settings := pEntryPoints.settings;
	instance.ContextSize := pEntryPoints.ContextSize;
	instance.ContextNew := nil;// freerdp_client_common_new;
	instance.ContextFree := nil;// freerdp_client_common_free;
	instance.pClientEntryPoints := GetMemory(pEntryPoints.Size);

	if instance.pClientEntryPoints = nil then
		goto out_fail;

	CopyMemory(instance.pClientEntryPoints, pEntryPoints, pEntryPoints.Size);

	if not freerdp_context_new(instance) then
		goto out_fail2;

	context := instance.context;
	context.instance := instance;
	context.settings := instance.settings;

//	if (freerdp_register_addin_provider(freerdp_channels_load_static_addin_entry,
//	                                    0) != CHANNEL_RC_OK)
//		goto out_fail2;

	Exit(context);
out_fail2:
	FreeMemory(instance.pClientEntryPoints);
out_fail:
	freerdp_free(instance);
	Exit(nil);
end;

procedure freerdp_client_context_free(context: PRdpContext);
var
	instance: PFreeRdp;
  pEntryPoints: PRdpClientEntryPoints;
begin
	if context = nil then
		Exit;

	instance := context.instance;

	if instance <> nil then
	begin
		pEntryPoints := instance.pClientEntryPoints;
		freerdp_context_free(instance);

		if pEntryPoints <> nil then
			IfCall(pEntryPoints.GlobalUninit);

		FreeMemory(instance.pClientEntryPoints);
		freerdp_free(instance);
	end;
end;

function freerdp_client_start(context: PRdpContext): Integer;
var
	pEntryPoints: PRdpClientEntryPoints;
begin
	if (context = nil) or (context.instance = nil) or (context.instance.pClientEntryPoints = nil) then
		Exit(ERROR_BAD_ARGUMENTS);

	pEntryPoints := context.instance.pClientEntryPoints;
	Result := IfCallResult(CHANNEL_RC_OK, pEntryPoints.ClientStart, context);
end;

function freerdp_client_stop(context: PRdpContext): Integer;
var
	pEntryPoints: PRdpClientEntryPoints;
begin
	if (context = nil) or (context.instance = nil) or (context.instance.pClientEntryPoints = nil) then
		Exit(ERROR_BAD_ARGUMENTS);

	pEntryPoints := context.instance.pClientEntryPoints;
	Result := IfCallResult(CHANNEL_RC_OK, pEntryPoints.ClientStop, context);
end;

end.
