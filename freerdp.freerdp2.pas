unit freerdp.freerdp2;

{
https://github.com/FreeRDP/FreeRDP.git
Revision: 3051a4b4b4cc99d8b580b34975579bf21885dc8c
Date: 01.08.2019 17:01:11
}


interface

{$INCLUDE jedi.inc}

uses
  System.SysUtils, Winapi.Windows;

const
  LIBFREERDP_DLL = 'freerdp2.dll';

type
  PRdpRdp = ^TRdpRdp;
  PFreeRdp = ^TFreeRdp;
  PRdpContext = ^TRdpContext;
  PRdpSettings = ^TRdpSettings;

{$REGION 'freerdp.h'}
  (**
   * Defines the context for a given instance of RDP connection.
   * It is embedded in the rdp_freerdp structure, and allocated by a call to freerdp_context_new().
   * It is deallocated by a call to freerdp_context_free().
   *)
  rdp_context = record
    {ALIGN64} instance: PFreeRdp; (**< (offset 0)
                Pointer to a rdp_freerdp structure.
                This is a back-link to retrieve the freerdp instance from the context.
                It is set by the freerdp_context_new() function *)
    {$IFDEF CPU32}padding4: UInt32;{$ENDIF}


    {ALIGN64} peer: Pointer; (**< (offset 1)
                 Pointer to the client peer.
                 This is set by a call to freerdp_peer_context_new() during peer initialization.
                 This field is used only on the server side. *)
    {$IFDEF CPU32}padding12: UInt32;{$ENDIF}

    {ALIGN64} ServerMode: BOOL; (**< (offset 2) true when context is in server mode *)
    {$IFDEF CPU32}padding20: UInt32;{$ENDIF}

    {ALIGN64} LastError: UINT32; (* 3 *)
    {$IFDEF CPU32}padding28: UInt32;{$ENDIF}

    paddingA: array[0..Pred(16 - 4)] of UINT64; (* 4 *)

    {ALIGN64} argc: Integer;	(**< (offset 16)
             Number of arguments given to the program at launch time.
             Used to keep this data available and used later on, typically just before connection initialization.
             @see freerdp_parse_args() *)
    {$IFDEF CPU32}padding132: UInt32;{$ENDIF}

    {ALIGN64} argv: PPAnsiChar; (**< (offset 17)
            List of arguments given to the program at launch time.
            Used to keep this data available and used later on, typically just before connection initialization.
            @see freerdp_parse_args() *)
    {$IFDEF CPU32}padding140: UInt32;{$ENDIF}

    {ALIGN64} pubSub: Pointer; (* (offset 18) *)
    {$IFDEF CPU32}padding148: UInt32;{$ENDIF}

    {ALIGN64} channelErrorEvent: THandle; (* (offset 19)*)
    {$IFDEF CPU32}padding156: UInt32;{$ENDIF}

    {ALIGN64} channelErrorNum: UINT; (*(offset 20)*)
    {$IFDEF CPU32}padding164: UInt32;{$ENDIF}

    {ALIGN64} errorDescription: PAnsiChar; (*(offset 21)*)
    {$IFDEF CPU32}padding172: UInt32;{$ENDIF}

    paddingB: array[0..Pred(32 - 22)] of UINT64; (* 22 *)

    {ALIGN64} rdp: PRdpRdp; (**< (offset 32)
            Pointer to a rdp_rdp structure used to keep the connection's parameters.
            It is allocated by freerdp_context_new() and deallocated by freerdp_context_free(), at the same
            time that this rdp_context structure - there is no need to specifically allocate/deallocate this. *)
    {$IFDEF CPU32}padding260: UInt32;{$ENDIF}

    {ALIGN64} gdi: Pointer; {^rdpGdi;} (**< (offset 33)
            Pointer to a rdp_gdi structure used to keep the gdi settings.
            It is allocated by gdi_init() and deallocated by gdi_free().
            It must be deallocated before deallocating this rdp_context structure. *)

    {ALIGN64} rail: Pointer{^rdpRail}; (* 34 *)
    {ALIGN64} cache: Pointer{^rdpCache}; (* 35 *)
    {ALIGN64} channels: Pointer{^rdpChannels}; (* 36 *)
    {ALIGN64} graphics: Pointer{^rdpGraphics}; (* 37 *)
    {ALIGN64} input: Pointer{^rdpInput}; (* 38 *)
    {ALIGN64} update: Pointer{^rdpUpdate}; (* 39 *)
    {ALIGN64} settings: PRdpSettings; (* 40 *)
    {ALIGN64} metrics: Pointer{^rdpMetrics}; (* 41 *)
    {ALIGN64} codecs: Pointer{^rdpCodecs}; (* 42 *)
    {ALIGN64} autodetect: Pointer{^rdpAutoDetect}; (* 43 *)
    {ALIGN64} abortEvent: THandle; (* 44 *)
    {ALIGN64} disconnectUltimatum: Integer; (* 45 *)
    paddingC: array[0..Pred(64 - 46)] of UINT64; (* 46 *)

    paddingD: array[0..Pred(96 - 64)] of UINT64; (* 64 *)
    paddingE: array[0..Pred(128 - 96)] of UINT64; (* 96 *)
  end;
  rdpContext = rdp_context;
  TRdpContext = rdpContext;

  rdp_input = record
  end;
  rdpInput = rdp_input;

  rdp_update = record
  end;
  rdpUpdate = rdp_update;

  rdp_autodetect = record
  end;
  rdpAutoDetect = rdp_autodetect;

  pRdpGlobalInit = function: BOOL; cdecl;
  pRdpGlobalUninit = procedure; cdecl;

  pRdpClientNew = function(instance: PFreerdp; context: PRdpContext): BOOL; cdecl;
  pRdpClientFree = procedure(instance: PFreerdp; context: PRdpContext); cdecl;

  pRdpClientStart = function(context: PRdpContext): Integer; cdecl;
  pRdpClientStop = function(context: PRdpContext): Integer; cdecl;

  rdp_client_entry_points_v1 = record
    Size: DWORD;
    Version: DWORD;

    settings: PRdpSettings;

    GlobalInit: pRdpGlobalInit;
    GlobalUninit: pRdpGlobalUninit;

    ContextSize: DWORD;
    ClientNew: pRdpClientNew;
    ClientFree: pRdpClientFree;

    ClientStart: pRdpClientStart;
    ClientStop: pRdpClientStop;
  end;
  RDP_CLIENT_ENTRY_POINTS = rdp_client_entry_points_v1;
  TRdpClientEntryPoints = RDP_CLIENT_ENTRY_POINTS;
  PRdpClientEntryPoints = ^TRdpClientEntryPoints;

  pContextNew = function(instance: PFreerdp; context: PRdpContext): BOOL; cdecl;
  pContextFree = procedure(instance: PFreerdp; context: PRdpContext); cdecl;

  pPreConnect = function (instance: PFreerdp): BOOL; cdecl;
  pPostConnect = function (instance: PFreerdp): BOOL; cdecl;
  pPostDisconnect = procedure (instance: PFreerdp); cdecl;
  pAuthenticate = function(instance: PFreerdp; username, password, domain: PPAnsiChar): BOOL; cdecl;

(** @brief Callback used if user interaction is required to accept
 *         an unknown certificate.
 *
 *  @deprecated Use pVerifyCertificateEx
 *  @param common_name      The certificate registered hostname.
 *  @param subject          The common name of the certificate.
 *  @param issuer           The issuer of the certificate.
 *  @param fingerprint      The fingerprint of the certificate.
 *  @param host_mismatch    A flag indicating the certificate
 *                          subject does not match the host connecting to.
 *
 *  @return 1 to accept and store a certificate, 2 to accept
 *          a certificate only for this session, 0 otherwise.
 *)
  pVerifyCertificate = function(instance: PFreerdp; const common_name, subject,
    issuer, fingerprint: PAnsiChar; host_mismatch: BOOL): DWORD; cdecl;

(** @brief Callback used if user interaction is required to accept
 *         an unknown certificate.
 *
 *  @param host             The hostname connecting to.
 *  @param port             The port connecting to.
 *  @param common_name      The certificate registered hostname.
 *  @param subject          The common name of the certificate.
 *  @param issuer           The issuer of the certificate.
 *  @param fingerprint      The fingerprint of the certificate.
 *  @param flags            Flags of type VERIFY_CERT_FLAG*
 *
 *  @return 1 to accept and store a certificate, 2 to accept
 *          a certificate only for this session, 0 otherwise.
 *)
  pVerifyCertificateEx = function(instance: PFreerdp; const host: PAnsiChar; port: UINT16;
    const common_name, subject, issuer, fingerprint: PAnsiChar; flags: DWORD): DWORD; cdecl;

(** @brief Callback used if user interaction is required to accept
 *         a changed certificate.
 *
 *  @deprecated Use pVerifyChangedCertificateEx
 *  @param common_name      The certificate registered hostname.
 *  @param subject          The common name of the new certificate.
 *  @param issuer           The issuer of the new certificate.
 *  @param fingerprint      The fingerprint of the new certificate.
 *  @param old_subject      The common name of the old certificate.
 *  @param old_issuer       The issuer of the new certificate.
 *  @param old_fingerprint  The fingerprint of the old certificate.
 *
 *  @return 1 to accept and store a certificate, 2 to accept
 *          a certificate only for this session, 0 otherwise.
 *)
  pVerifyChangedCertificate = function(instance: PFreerdp; const common_name, subject,
    issuer, new_fingerprint, old_subject, old_issuer, old_fingerprint: PAnsiChar): DWORD; cdecl;

(** @brief Callback used if user interaction is required to accept
 *         a changed certificate.
 *
 *  @param host             The hostname connecting to.
 *  @param port             The port connecting to.
 *  @param common_name      The certificate registered hostname.
 *  @param subject          The common name of the new certificate.
 *  @param issuer           The issuer of the new certificate.
 *  @param fingerprint      The fingerprint of the new certificate.
 *  @param old_subject      The common name of the old certificate.
 *  @param old_issuer       The issuer of the new certificate.
 *  @param old_fingerprint  The fingerprint of the old certificate.
 *  @param flags            Flags of type VERIFY_CERT_FLAG*
 *
 *  @return 1 to accept and store a certificate, 2 to accept
 *          a certificate only for this session, 0 otherwise.
 *)
  pVerifyChangedCertificateEx = function(instance: PFreerdp; const host: PAnsiChar;
    port: UINT16; const common_name, subject, issuer, new_fingerprint, old_subject,
    old_issuer, old_fingerprint: PAnsiChar; flags: DWORD): DWORD; cdecl;

(** @brief Callback used if user interaction is required to accept
 *         a certificate.
 *
 *  @param instance         Pointer to the freerdp instance.
 *  @param data             Pointer to certificate data in PEM format.
 *  @param length           The length of the certificate data.
 *  @param hostname         The hostname connecting to.
 *  @param port             The port connecting to.
 *  @param flags            Flags of type VERIFY_CERT_FLAG*
 *
 *  @return 1 to accept and store a certificate, 2 to accept
 *          a certificate only for this session, 0 otherwise.
 *)
  pVerifyX509Certificate = function(instance: PFreerdp; const data: PByte; length: size_t;
    const hostname: PAnsiChar; port: UINT16; flags: DWORD): Integer; cdecl;

  pLogonErrorInfo = function(instance: PFreerdp; data: UINT32; type_: UINT32): Integer; cdecl;

  pSendChannelData = function(instance: PFreerdp; channelId: UINT16; data: PByte; size: Integer): Integer; cdecl;

  pReceiveChannelData = function(instance: PFreerdp; channelId: UINT16; data: PByte;
    size, flags, totalSize: Integer): Integer; cdecl;

  pPresentGatewayMessage = function(instance: PFreerdp; type_: UINT32; isDisplayMandatory: BOOL;
    isConsentMandatory: BOOL; length: size_t; const message_: PWideChar): BOOL; cdecl;

  (** Defines the options for a given instance of RDP connection.
   *  This is built by the client and given to the FreeRDP library to create the connection
   *  with the expected options.
   *  It is allocated by a call to freerdp_new() and deallocated by a call to freerdp_free().
   *  Some of its content need specific allocation/deallocation - see field description for details.
   *)
  (*
    ALIGN64 это макрос для __declspec(align(8))
    т.е. каждое поле должно быть выровнено по 8байт (64бита)
    и т.к. delphi  этого не умеет делать автоматически,
    пришлось добавить отступы (paddingXXX) вручную для 32битного компилятора.
    А у 64битного указатели и так 8байтные
  *)

  rdp_freerdp = record {640bytes}
    {ALIGN64} context: PRdpContext; (**< (offset 0)
               Pointer to a rdpContext structure.
               Client applications can use the ContextSize field to register a context bigger than the rdpContext
               structure. This allow clients to use additional context information.
               When using this capability, client application should ALWAYS declare their structure with the
               rdpContext field first, and any additional content following it.
               Can be allocated by a call to freerdp_context_new().
               Must be deallocated by a call to freerdp_context_free() before deallocating the current instance. *)
    {$IFDEF CPU32}padding4: UInt32;{$ENDIF}

    {ALIGN64} pClientEntryPoints: PRdpClientEntryPoints;
    {$IFDEF CPU32}padding12: UInt32;{$ENDIF}

    paddingA: array[0..(16-2)-1] of UINT64; (* 2 *)

    {ALIGN64} input: ^rdpInput; (* (offset 16)
           Input handle for the connection.
           Will be initialized by a call to freerdp_context_new() *)
    {$IFDEF CPU32}padding132: UInt32;{$ENDIF}

    {ALIGN64} update: ^rdpUpdate; (* (offset 17)
             Update display parameters. Used to register display events callbacks and settings.
             Will be initialized by a call to freerdp_context_new() *)
    {$IFDEF CPU32}padding140: UInt32;{$ENDIF}

    {ALIGN64} settings: PRdpSettings; (**< (offset 18)
               Pointer to a rdpSettings structure. Will be used to maintain the required RDP settings.
               Will be initialized by a call to freerdp_context_new() *)
    {$IFDEF CPU32}padding148: UInt32;{$ENDIF}

    {ALIGN64} autodetect: ^rdpAutoDetect; (* (offset 19)
                 Auto-Detect handle for the connection.
                 Will be initialized by a call to freerdp_context_new() *)
    {$IFDEF CPU32}padding156: UInt32;{$ENDIF}

    paddingB: array[0..(32-20)-1] of UINT64; {(* 20 *)}

    {ALIGN64} ContextSize: size_t; (* (offset 32)
             Specifies the size of the 'context' field. freerdp_context_new() will use this size to allocate the context buffer.
             freerdp_new() sets it to sizeof(rdpContext).
             If modifying it, there should always be a minimum of sizeof(rdpContext), as the freerdp library will assume it can use the
             'context' field to set the required informations in it.
             Clients will typically make it bigger, and use a context structure embedding the rdpContext, and
             adding additional information after that.
            *)
    {$IFDEF CPU32}padding260: UInt32;{$ENDIF}

    {ALIGN64} ContextNew: pContextNew; (**< (offset 33)
                Callback for context allocation
                Can be set before calling freerdp_context_new() to have it executed after allocation and initialization.
                Must be set to NULL if not needed. *)
    {$IFDEF CPU32}padding268: UInt32;{$ENDIF}

    {ALIGN64} ContextFree: pContextFree; (**< (offset 34)
                  Callback for context deallocation
                  Can be set before calling freerdp_context_free() to have it executed before deallocation.
                  Must be set to NULL if not needed. *)
    {$IFDEF CPU32}padding276: UInt32;{$ENDIF}

    paddingC: array[0..(47-35)-1] of UINT64; {(* 35 *)}

    {ALIGN64} ConnectionCallbackState: Cardinal; {(* 47 *)}
    {!$IFNDEF CPU64}padding380: UInt32;{!$ENDIF}

    {ALIGN64} PreConnect: pPreConnect; (**< (offset 48)
                Callback for pre-connect operations.
                Can be set before calling freerdp_connect() to have it executed before the actual connection happens.
                Must be set to NULL if not needed. *)
    {$IFDEF CPU32}padding388: UInt32;{$ENDIF}

    {ALIGN64} PostConnect: pPostConnect; (**< (offset 49)
                  Callback for post-connect operations.
                  Can be set before calling freerdp_connect() to have it executed after the actual connection has succeeded.
                  Must be set to NULL if not needed. *)
    {$IFDEF CPU32}padding396: UInt32;{$ENDIF}

    {ALIGN64} Authenticate: pAuthenticate; (**< (offset 50)
                  Callback for authentication.
                  It is used to get the username/password when it was not provided at connection time. *)
    {$IFDEF CPU32}padding404: UInt32;{$ENDIF}

    {ALIGN64} VerifyCertificate: pVerifyCertificate; (**< (offset 51)
                        Callback for certificate validation.
                        Used to verify that an unknown certificate is trusted. *)
    {$IFDEF CPU32}padding412: UInt32;{$ENDIF}

    {DEPRECATED: Use VerifyChangedCertificateEx*}
    {ALIGN64} VerifyChangedCertificate: pVerifyChangedCertificate; (**< (offset 52)
                              Callback for changed certificate validation.
                              Used when a certificate differs from stored fingerprint. *)
    {$IFDEF CPU32}padding420: UInt32;{$ENDIF}

    {DEPRECATED: Use VerifyChangedCertificateEx *)}
    {ALIGN64} VerifyX509Certificate: pVerifyX509Certificate;  (**< (offset 53)  Callback for X509 certificate verification (PEM format) *)
    {$IFDEF CPU32}padding428: UInt32;{$ENDIF}

    {ALIGN64} LogonErrorInfo: pLogonErrorInfo; (**< (offset 54)  Callback for logon error info, important for logon system messages with RemoteApp *)
    {$IFDEF CPU32}padding436: UInt32;{$ENDIF}

    {ALIGN64} PostDisconnect: pPostDisconnect; (**< (offset 55)
                                           Callback for cleaning up resources allocated
                                           by connect callbacks. *)
    {$IFDEF CPU32}padding444: UInt32;{$ENDIF}

    {ALIGN64} GatewayAuthenticate: pAuthenticate; (**< (offset 56)
                  Callback for gateway authentication.
                  It is used to get the username/password when it was not provided at connection time. *)
    {$IFDEF CPU32}padding452: UInt32;{$ENDIF}

    {ALIGN64} PresentGatewayMessage: pPresentGatewayMessage; (**< (offset 57)
                  Callback for gateway consent messages.
                  It is used to present consent messages to the user. *)
    {$IFDEF CPU32}padding460: UInt32;{$ENDIF}

    paddingD: array[0..(64-58)-1] of UINT64; {(* 58 *)}

    {ALIGN64} SendChannelData: pSendChannelData; (* (offset 64)
                    Callback for sending data to a channel.
                    By default, it is set by freerdp_new() to freerdp_send_channel_data(), which eventually calls
                    freerdp_channel_send() *)
    {$IFDEF CPU32}padding516: UInt32;{$ENDIF}

    {ALIGN64} ReceiveChannelData: pReceiveChannelData; (* (offset 65)
                        Callback for receiving data from a channel.
                        This is called by freerdp_channel_process() (if not NULL).
                        Clients will typically use a function that calls freerdp_channels_data() to perform the needed tasks. *)
    {$IFDEF CPU32}padding524: UInt32;{$ENDIF}

    {ALIGN64} VerifyCertificateEx: pVerifyCertificateEx; (**< (offset 66)
                        Callback for certificate validation.
                        Used to verify that an unknown certificate is trusted. *)
    {$IFDEF CPU32}padding532: UInt32;{$ENDIF}

    {ALIGN64} VerifyChangedCertificateEx: pVerifyChangedCertificateEx; (**< (offset 67)
                              Callback for changed certificate validation.
                              Used when a certificate differs from stored fingerprint. *)
    {$IFDEF CPU32}padding540: UInt32;{$ENDIF}

    paddingE: array[0..(80-68)-1] of UINT64 ; (* 68 *)
  end;                     {+12}

  freerdp = rdp_freerdp;
  TFreeRdp = freerdp;

  rdp_rdp = record
    state: Integer;
    instance: ^freerdp;
    context: ^rdpContext;
    nla: Pointer{^rdpNla};
    mcs: Pointer{^rdpMcs};
    nego: Pointer{^rdpNego};
    bulk: Pointer{^rdpBulk};
    input: Pointer{^rdpInput};
    update: Pointer{^rdpUpdate};
    fastpath: Pointer{^rdpFastPath};
    license: Pointer{^rdpLicense};
    redirection: Pointer{^rdpRedirection};
    settings: Pointer{^rdpSettings};
    transport: Pointer{^rdpTransport};
    autodetect: Pointer{^rdpAutoDetect};
    heartbeat: Pointer{^rdpHeartbeat};
    multitransport: Pointer{^rdpMultitransport};
    rc4_decrypt_key: Pointer{^WINPR_RC4_CTX};
    decrypt_use_count: Integer;
    decrypt_checksum_use_count: Integer;
    rc4_encrypt_key: Pointer{^WINPR_RC4_CTX};
    encrypt_use_count: integer;
    encrypt_checksum_use_count: integer;
    fips_encrypt: Pointer{^WINPR_CIPHER_CTX};
    fips_decrypt: Pointer{^WINPR_CIPHER_CTX};
    sec_flags: UINT32;
    do_crypt: BOOL;
    do_crypt_license: BOOL;
    do_secure_checksum: BOOL;
    sign_key: array [0..Pred(16)] of BYTE;
    decrypt_key: array [0..Pred(16)] of BYTE;
    encrypt_key: array [0..Pred(16)] of BYTE;
    decrypt_update_key: array [0..Pred(16)] of BYTE;
    encrypt_update_key: array [0..Pred(16)] of BYTE;
    rc4_key_len: integer;
    fips_sign_key: array [0..Pred(20)] of BYTE;
    fips_encrypt_key: array [0..Pred(24)] of BYTE;
    fips_decrypt_key: array [0..Pred(24)] of BYTE;
    errorInfo: UINT32;
    finalize_sc_pdus: UINT32;
    resendFocus: BOOL;
    deactivation_reactivation: BOOL;
    AwaitCapabilities: BOOL;
  end;
  TRdpRdp = rdp_rdp;

  (* ARC_CS_PRIVATE_PACKET *)
  ARC_CS_PRIVATE_PACKET = record
    cbLen: UINT32;
    version: UINT32;
    logonId: UINT32;
    securityVerifier: array [0..Pred(16)] of BYTE;
  end;

  (* ARC_SC_PRIVATE_PACKET *)
  ARC_SC_PRIVATE_PACKET = record
    cbLen: UINT32;
    version: UINT32;
    logonId: UINT32;
    arcRandomBits: array [0..Pred(16)] of BYTE;
  end;

(* Certificates *)

  rdp_CertBlob = record
    length: UINT32;
    data: pBYTE;
  end;
  rdpCertBlob = rdp_CertBlob;

  TArrayOfBytes = array[0..0] of Byte;
  PArrayOfBytes = TArrayOfBytes;

  rdp_X509CertChain = record
    count: UINT32;
    prdpCertBlob: PArrayOfBytes;
  end;
  rdpX509CertChain = rdp_X509CertChain;

  rdp_CertInfo = record
    Modulus: pBYTE;
    ModulusLength: DWORD;
    exponent: array [0..Pred(4)] of BYTE;
  end;
  rdpCertInfo = rdp_CertInfo;

  rdp_certificate = record
    cert_info: rdpCertInfo;
    x509_cert_chain: ^rdpX509CertChain;
  end;
  rdpCertificate = rdp_certificate;

  rdp_rsa_key = record
    Modulus: pBYTE;
    ModulusLength: DWORD;
    PrivateExponent: pBYTE;
    PrivateExponentLength: DWORD;
    exponent: array [0..Pred(4)] of BYTE;
  end;
  rdpRsaKey = rdp_rsa_key;

  (* Channels *)
  _ADDIN_ARGV = record
    argc: integer;
    argv: PPAnsiChar;
  end;
  ADDIN_ARGV = _ADDIN_ARGV;
  TAddinArgv = ADDIN_ARGV;
  PAddinArgv = ^TAddinArgv;
  PPAddinArgv = ^PAddinArgv;

  (* Extensions *)
  rdp_ext_set = record
    name: array [0..Pred(256)] of AnsiChar; (* plugin name or path *)
    data: Pointer; (* plugin data *)
  end;

  (* Bitmap Cache *)
  _BITMAP_CACHE_CELL_INFO = record
    numEntries: UINT16;
    maxSize: UINT16;
  end;
  BITMAP_CACHE_CELL_INFO = _BITMAP_CACHE_CELL_INFO;

  _BITMAP_CACHE_V2_CELL_INFO = record
    numEntries: UINT32;
    persistent: BOOL;
  end;
  BITMAP_CACHE_V2_CELL_INFO = _BITMAP_CACHE_V2_CELL_INFO;

  (* Glyph Cache *)
  _GLYPH_CACHE_DEFINITION = record
    cacheEntries: UINT16;
    cacheMaximumCellSize: UINT16;
  end;
  GLYPH_CACHE_DEFINITION = _GLYPH_CACHE_DEFINITION;

  (* Monitors *)

  _MONITOR_DEF = record
    left: INT32;
    top: INT32;
    right: INT32;
    bottom: INT32;
    flags: UINT32;
  end;
  MONITOR_DEF = _MONITOR_DEF;

  _MONITOR_ATTRIBUTES = record
    physicalWidth: UINT32;
    physicalHeight: UINT32;
    orientation: UINT32;
    desktopScaleFactor: UINT32;
    deviceScaleFactor: UINT32;
  end;
  MONITOR_ATTRIBUTES = _MONITOR_ATTRIBUTES;

  rdp_monitor = record
    x: INT32;
    y: INT32;
    width: INT32;
    height: INT32;
    is_primary: UINT32;
    orig_screen: UINT32;
    attributes: MONITOR_ATTRIBUTES;
  end;
  rdpMonitor = rdp_monitor;

  rdp_settings = record {46688 bytes}
	(**
	 * WARNING: this data structure is carefully padded for ABI stability!
	 * Keeping this area clean is particularly challenging, so unless you are
	 * a trusted developer you should NOT take the liberty of adding your own
	 * options straight into the ABI stable zone. Instead, append them to the
	 * very end of this data structure, in the zone marked as ABI unstable.
	 *)

	{ALIGN64} instance: Pointer;                   (* 0 *)  {$IFDEF CPU32} _padding4: UInt32; {$ENDIF}
	padding001: array[0..Pred(16 - 1)] of UINT64;  (* 1 *)

	(* Core Parameters *)
	{ALIGN64} ServerMode: BOOL;                    (* 16 *)  {$IFDEF CPU32} padding132: UInt32; {$ENDIF}
	{ALIGN64} ShareId: UINT32;                     (* 17 *)  {$IFDEF CPU32} padding140: UInt32; {$ENDIF}
	{ALIGN64} PduSource: UINT32;                   (* 18 *)  {$IFDEF CPU32} padding148: UInt32; {$ENDIF}
	{ALIGN64} ServerPort: UINT32;                  (* 19 *)  {$IFDEF CPU32} padding156: UInt32; {$ENDIF}
	{ALIGN64} ServerHostname: PAnsiChar;           (* 20 *)  {$IFDEF CPU32} padding164: UInt32; {$ENDIF}
	{ALIGN64} Username: PAnsiChar;                 (* 21 *)  {$IFDEF CPU32} padding172: UInt32; {$ENDIF}
	{ALIGN64} Password: PAnsiChar;                 (* 22 *)  {$IFDEF CPU32} padding180: UInt32; {$ENDIF}
	{ALIGN64} Domain: PAnsiChar;                   (* 23 *)  {$IFDEF CPU32} padding188: UInt32; {$ENDIF}
	{ALIGN64} PasswordHash: PAnsiChar;             (* 24 *)  {$IFDEF CPU32} padding196: UInt32; {$ENDIF}
	{ALIGN64} WaitForOutputBufferFlush: BOOL;      (* 25 *)  {$IFDEF CPU32} padding204: UInt32; {$ENDIF}
	{ALIGN64} MaxTimeInCheckLoop: UINT32;          (* 26 *)  {$IFDEF CPU32} padding212: UInt32; {$ENDIF}
	{ALIGN64} AcceptedCert: PAnsiChar;             (* 27 *)  {$IFDEF CPU32} padding220: UInt32; {$ENDIF}
	{ALIGN64} AcceptedCertLength: UINT32;          (* 28 *)  {$IFDEF CPU32} padding228: UInt32; {$ENDIF}
	padding0064: array[0..Pred(64 - 29)] of UInt64; (* 29 *)
	padding0128: array[0..Pred(128 - 64)] of UInt64; (* 64 *)

	(**
	 * GCC User Data Blocks
	 *)

	(* Client/Server Core Data *)
	{ALIGN64} RdpVersion: UINT32;              (* 128 *)  {$IFDEF CPU32} padding1028: UInt32; {$ENDIF}
	{ALIGN64} DesktopWidth: UINT32;            (* 129 *)  {$IFDEF CPU32} padding1036: UInt32; {$ENDIF}
	{ALIGN64} DesktopHeight: UINT32;           (* 130 *)  {$IFDEF CPU32} padding1044: UInt32; {$ENDIF}
	{ALIGN64} ColorDepth: UINT32;              (* 131 *)  {$IFDEF CPU32} padding1052: UInt32; {$ENDIF}
	{ALIGN64} ConnectionType: UINT32;          (* 132 *)  {$IFDEF CPU32} padding1060: UInt32; {$ENDIF}
	{ALIGN64} ClientBuild: UINT32;             (* 133 *)  {$IFDEF CPU32} padding1068: UInt32; {$ENDIF}
	{ALIGN64} ClientHostname: PAnsiChar;       (* 134 *)  {$IFDEF CPU32} padding1076: UInt32; {$ENDIF}
	{ALIGN64} ClientProductId: PAnsiChar;      (* 135 *)  {$IFDEF CPU32} padding1084: UInt32; {$ENDIF}
	{ALIGN64} EarlyCapabilityFlags: UINT32;    (* 136 *)  {$IFDEF CPU32} padding1092: UInt32; {$ENDIF}
	{ALIGN64} NetworkAutoDetect: BOOL;         (* 137 *)  {$IFDEF CPU32} padding1100: UInt32; {$ENDIF}
	{ALIGN64} SupportAsymetricKeys: BOOL;      (* 138 *)  {$IFDEF CPU32} padding1108: UInt32; {$ENDIF}
	{ALIGN64} SupportErrorInfoPdu: BOOL;       (* 139 *)  {$IFDEF CPU32} padding1116: UInt32; {$ENDIF}
	{ALIGN64} SupportStatusInfoPdu: BOOL;      (* 140 *)  {$IFDEF CPU32} padding1124: UInt32; {$ENDIF}
	{ALIGN64} SupportMonitorLayoutPdu: BOOL;   (* 141 *)  {$IFDEF CPU32} padding1132: UInt32; {$ENDIF}
	{ALIGN64} SupportGraphicsPipeline: BOOL;   (* 142 *)  {$IFDEF CPU32} padding1140: UInt32; {$ENDIF}
	{ALIGN64} SupportDynamicTimeZone: BOOL;    (* 143 *)  {$IFDEF CPU32} padding1148: UInt32; {$ENDIF}
	{ALIGN64} SupportHeartbeatPdu: BOOL;       (* 144 *)  {$IFDEF CPU32} padding1156: UInt32; {$ENDIF}
	{ALIGN64} DesktopPhysicalWidth: UINT32;    (* 145 *)  {$IFDEF CPU32} padding1164: UInt32; {$ENDIF}
	{ALIGN64} DesktopPhysicalHeight: UINT32;   (* 146 *)  {$IFDEF CPU32} padding1172: UInt32; {$ENDIF}
	{ALIGN64} DesktopOrientation: UINT16;      (* 147 *)  {$IFDEF CPU32} padding1178: UInt16; padding1180: UInt32; {$ENDIF}
	{ALIGN64} DesktopScaleFactor: UINT32;      (* 148 *)  {$IFDEF CPU32} padding1188: UInt32; {$ENDIF}
	{ALIGN64} DeviceScaleFactor: UINT32;       (* 149 *)  {$IFDEF CPU32} padding1196: UInt32; {$ENDIF}
	padding0192: array[0..Pred(192 - 150)] of UInt64; (* 150 *)

	(* Client/Server Security Data *)
	{ALIGN64} UseRdpSecurityLayer: BOOL;       (* 192 *)  {$IFDEF CPU32} padding1540: UInt32; {$ENDIF}
	{ALIGN64} EncryptionMethods: UINT32;       (* 193 *)  {$IFDEF CPU32} padding1548: UInt32; {$ENDIF}
	{ALIGN64} ExtEncryptionMethods: UINT32;    (* 194 *)  {$IFDEF CPU32} padding1556: UInt32; {$ENDIF}
	{ALIGN64} EncryptionLevel: UINT32;         (* 195 *)  {$IFDEF CPU32} padding1564: UInt32; {$ENDIF}
	{ALIGN64} ServerRandom: PByte;             (* 196 *)  {$IFDEF CPU32} padding1572: UInt32; {$ENDIF}
	{ALIGN64} ServerRandomLength: UINT32;      (* 197 *)  {$IFDEF CPU32} padding1580: UInt32; {$ENDIF}
	{ALIGN64} ServerCertificate: PByte;        (* 198 *)  {$IFDEF CPU32} padding1588: UInt32; {$ENDIF}
	{ALIGN64} ServerCertificateLength: UINT32; (* 199 *)  {$IFDEF CPU32} padding1596: UInt32; {$ENDIF}
	{ALIGN64} ClientRandom: PByte;             (* 200 *)  {$IFDEF CPU32} padding1604: UInt32; {$ENDIF}
	{ALIGN64} ClientRandomLength: UINT32;      (* 201 *)  {$IFDEF CPU32} padding1612: UInt32; {$ENDIF}
	padding0256: array[0..Pred(256 - 202)] of UInt64; (* 202 *)

	(* Client Network Data *)
	{ALIGN64} ChannelCount: UINT32;              (* 256 *)  {$IFDEF CPU32} padding2052: UInt32; {$ENDIF}
	{ALIGN64} ChannelDefArraySize: UINT32;       (* 257 *)  {$IFDEF CPU32} padding2060: UInt32; {$ENDIF}
	{ALIGN64} ChannelDefArray: Pointer;          (* 258 *)  {$IFDEF CPU32} padding2068: UInt32; {$ENDIF}
	padding0320: array[0..Pred(320 - 259)] of UINT64; (* 259 *)

	(* Client Cluster Data *)
	{ALIGN64} ClusterInfoFlags: UINT32;    (* 320 *)  {$IFDEF CPU32} padding2564: UInt32; {$ENDIF}
	{ALIGN64} RedirectedSessionId: UINT32; (* 321 *)  {$IFDEF CPU32} padding2572: UInt32; {$ENDIF}
	{ALIGN64} ConsoleSession: BOOL;        (* 322 *)  {$IFDEF CPU32} padding2580: UInt32; {$ENDIF}
	padding0384: array[0..Pred(384 - 323)] of UINT64; (* 323 *)

	(* Client Monitor Data *)
	{ALIGN64} MonitorCount: UINT32;         (*    384 *)  {$IFDEF CPU32} padding3076: UInt32; {$ENDIF}
	{ALIGN64} MonitorDefArraySize: UINT32;  (*    385 *)  {$IFDEF CPU32} padding3084: UInt32; {$ENDIF}
	{ALIGN64} MonitorDefArray: Pointer;     (*    386 *)  {$IFDEF CPU32} padding3092: UInt32; {$ENDIF}
	{ALIGN64} SpanMonitors: BOOL;           (*    387 *)  {$IFDEF CPU32} padding3100: UInt32; {$ENDIF}
	{ALIGN64} UseMultimon: BOOL;            (*    388 *)  {$IFDEF CPU32} padding3108: UInt32; {$ENDIF}
	{ALIGN64} ForceMultimon: BOOL;          (*    389 *)  {$IFDEF CPU32} padding3116: UInt32; {$ENDIF}
	{ALIGN64} DesktopPosX: UINT32;          (*    390 *)  {$IFDEF CPU32} padding3124: UInt32; {$ENDIF}
	{ALIGN64} DesktopPosY: UINT32;          (*    391 *)  {$IFDEF CPU32} padding3132: UInt32; {$ENDIF}
	{ALIGN64} ListMonitors: BOOL;           (*    392 *)  {$IFDEF CPU32} padding3140: UInt32; {$ENDIF}
	{ALIGN64} MonitorIds: PUINT32;          (*    393 *)  {$IFDEF CPU32} padding3148: UInt32; {$ENDIF}
	{ALIGN64} NumMonitorIds: UINT32;        (*    394 *)  {$IFDEF CPU32} padding3156: UInt32; {$ENDIF}
	{ALIGN64} MonitorLocalShiftX: UINT32;   (*    395 *)  {$IFDEF CPU32} padding3164: UInt32; {$ENDIF}
	{ALIGN64} MonitorLocalShiftY: UINT32;   (*    396 *)  {$IFDEF CPU32} padding3172: UInt32; {$ENDIF}
	{ALIGN64} HasMonitorAttributes: BOOL;   (*    397 *)  {$IFDEF CPU32} padding3180: UInt32; {$ENDIF}
	padding0448: array[0..Pred(448 - 398)] of UINT64; (* 398 *)


	(* Client Message Channel Data *)
	padding0512: array[0..Pred(512 - 448)] of UINT64; (* 448 *)

	(* Client Multitransport Channel Data *)
	{ALIGN64} MultitransportFlags: UINT32;   (* 512 *)  {$IFDEF CPU32} padding4100: UInt32; {$ENDIF}
	{ALIGN64} SupportMultitransport: BOOL;   (* 513 *)  {$IFDEF CPU32} padding4108: UInt32; {$ENDIF}
	padding0576: array[0..Pred(576 - 514)] of UINT64; (* 514 *)
	padding0640: array[0..Pred(640 - 576)] of UINT64; (* 576 *)

	(*
	 * Client Info
	 *)

	(* Client Info (Shell) *)
	{ALIGN64} AlternateShell: PAnsiChar;        (* 640 *)  {$IFDEF CPU32} padding5124: UInt32; {$ENDIF}
	{ALIGN64} ShellWorkingDirectory: PAnsiChar; (* 641 *)  {$IFDEF CPU32} padding5132: UInt32; {$ENDIF}
	padding0704: array[0..Pred(704 - 642)] of UINT64; (* 642 *)

	(* Client Info Flags *)
	{ALIGN64} AutoLogonEnabled: BOOL;       (* 704 *)  {$IFDEF CPU32} padding5636: UInt32; {$ENDIF}
	{ALIGN64} CompressionEnabled: BOOL;     (* 705 *)  {$IFDEF CPU32} padding5644: UInt32; {$ENDIF}
	{ALIGN64} DisableCtrlAltDel: BOOL;      (* 706 *)  {$IFDEF CPU32} padding5652: UInt32; {$ENDIF}
	{ALIGN64} EnableWindowsKey: BOOL;       (* 707 *)  {$IFDEF CPU32} padding5660: UInt32; {$ENDIF}
	{ALIGN64} MaximizeShell: BOOL;          (* 708 *)  {$IFDEF CPU32} padding5668: UInt32; {$ENDIF}
	{ALIGN64} LogonNotify: BOOL;            (* 709 *)  {$IFDEF CPU32} padding5676: UInt32; {$ENDIF}
	{ALIGN64} LogonErrors: BOOL;            (* 710 *)  {$IFDEF CPU32} padding5684: UInt32; {$ENDIF}
	{ALIGN64} MouseAttached: BOOL;          (* 711 *)  {$IFDEF CPU32} padding5692: UInt32; {$ENDIF}
	{ALIGN64} MouseHasWheel: BOOL;          (* 712 *)  {$IFDEF CPU32} padding5700: UInt32; {$ENDIF}
	{ALIGN64} RemoteConsoleAudio: BOOL;     (* 713 *)  {$IFDEF CPU32} padding5708: UInt32; {$ENDIF}
	{ALIGN64} AudioPlayback: BOOL;          (* 714 *)  {$IFDEF CPU32} padding5716: UInt32; {$ENDIF}
	{ALIGN64} AudioCapture: BOOL;           (* 715 *)  {$IFDEF CPU32} padding5724: UInt32; {$ENDIF}
	{ALIGN64} VideoDisable: BOOL;           (* 716 *)  {$IFDEF CPU32} padding5732: UInt32; {$ENDIF}
	{ALIGN64} PasswordIsSmartcardPin: BOOL; (* 717 *)  {$IFDEF CPU32} padding5740: UInt32; {$ENDIF}
	{ALIGN64} UsingSavedCredentials: BOOL;  (* 718 *)  {$IFDEF CPU32} padding5748: UInt32; {$ENDIF}
	{ALIGN64} ForceEncryptedCsPdu: BOOL;    (* 719 *)  {$IFDEF CPU32} padding5756: UInt32; {$ENDIF}
	{ALIGN64} HiDefRemoteApp: BOOL;         (* 720 *)  {$IFDEF CPU32} padding5764: UInt32; {$ENDIF}
	{ALIGN64} CompressionLevel: UINT32;     (* 721 *)  {$IFDEF CPU32} padding5772: UInt32; {$ENDIF}
	padding0768: array[0..Pred(768 - 722)] of UINT64; (* 722 *)

	(* Client Info (Extra) *)
	{ALIGN64} IPv6Enabled: BOOL;         (* 768 *)  {$IFDEF CPU32} padding6148: UInt32; {$ENDIF}
	{ALIGN64} ClientAddress: PAnsiChar;  (* 769 *)  {$IFDEF CPU32} padding6156: UInt32; {$ENDIF}
	{ALIGN64} ClientDir: PAnsiChar;      (* 770 *)  {$IFDEF CPU32} padding6164: UInt32; {$ENDIF}
	padding0832: array[0..Pred(832 - 771)] of UINT64; (* 771 *)

	(* Client Info (Auto Reconnection) *)
	{ALIGN64} AutoReconnectionEnabled: BOOL;                     (* 832 *)  {$IFDEF CPU32} padding6660: UInt32; {$ENDIF}
	{ALIGN64} AutoReconnectMaxRetries: UINT32;                   (* 833 *)  {$IFDEF CPU32} padding6668: UInt32; {$ENDIF}
	{ALIGN64} ClientAutoReconnectCookie: Pointer;                (* 834 *)  {$IFDEF CPU32} padding6676: UInt32; {$ENDIF}
	{ALIGN64} ServerAutoReconnectCookie: Pointer;                (* 835 *)  {$IFDEF CPU32} padding6684: UInt32; {$ENDIF}
	{ALIGN64} PrintReconnectCookie: BOOL;                        (* 836 *)  {$IFDEF CPU32} padding6692: UInt32; {$ENDIF}
	padding0896: array[0..Pred(896 - 837)] of UINT64; (* 837 *)

	(* Client Info (Time Zone) *)
	{ALIGN64} ClientTimeZone: ^TIME_ZONE_INFORMATION;   (* 896 *)  {$IFDEF CPU32} padding7172: UInt32; {$ENDIF}
	{ALIGN64} DynamicDSTTimeZoneKeyName: PAnsiChar;     (* 897 *)  {$IFDEF CPU32} padding7180: UInt32; {$ENDIF}
	{ALIGN64} DynamicDaylightTimeDisabled: BOOL;        (* 898 *)  {$IFDEF CPU32} padding7188: UInt32; {$ENDIF}
	padding0960: array[0..Pred(960 - 899)] of UInt64; (* 899 *)

	(* Client Info (Performance Flags) *)
	{ALIGN64} PerformanceFlags: UINT32;      (* 960 *)  {$IFDEF CPU32} padding7684: UInt32; {$ENDIF}
	{ALIGN64} AllowFontSmoothing: BOOL;      (* 961 *)  {$IFDEF CPU32} padding7692: UInt32; {$ENDIF}
	{ALIGN64} DisableWallpaper: BOOL;        (* 962 *)  {$IFDEF CPU32} padding7700: UInt32; {$ENDIF}
	{ALIGN64} DisableFullWindowDrag: BOOL;   (* 963 *)  {$IFDEF CPU32} padding7708: UInt32; {$ENDIF}
	{ALIGN64} DisableMenuAnims: BOOL;        (* 964 *)  {$IFDEF CPU32} padding7716: UInt32; {$ENDIF}
	{ALIGN64} DisableThemes: BOOL;           (* 965 *)  {$IFDEF CPU32} padding7724: UInt32; {$ENDIF}
	{ALIGN64} DisableCursorShadow: BOOL;     (* 966 *)  {$IFDEF CPU32} padding7732: UInt32; {$ENDIF}
	{ALIGN64} DisableCursorBlinking: BOOL;   (* 967 *)  {$IFDEF CPU32} padding7740: UInt32; {$ENDIF}
	{ALIGN64} AllowDesktopComposition: BOOL; (* 968 *)  {$IFDEF CPU32} padding7748: UInt32; {$ENDIF}
	padding1024: array[0..Pred(1024 - 969)] of UInt64; (* 969 *)

	(* Remote Assistance *)
	{ALIGN64} RemoteAssistanceMode: BOOL;           (* 1024 *)  {$IFDEF CPU32} padding8196: UInt32; {$ENDIF}
	{ALIGN64} RemoteAssistanceSessionId: PAnsiChar; (* 1025 *)  {$IFDEF CPU32} padding8204: UInt32; {$ENDIF}
	{ALIGN64} RemoteAssistancePassStub: PAnsiChar;  (* 1026 *)  {$IFDEF CPU32} padding8212: UInt32; {$ENDIF}
	{ALIGN64} RemoteAssistancePassword: PAnsiChar;  (* 1027 *)  {$IFDEF CPU32} padding8220: UInt32; {$ENDIF}
	{ALIGN64} RemoteAssistanceRCTicket: PAnsiChar;  (* 1028 *)  {$IFDEF CPU32} padding8228: UInt32; {$ENDIF}
	{ALIGN64} EncomspVirtualChannel: BOOL;          (* 1029 *)  {$IFDEF CPU32} padding8236: UInt32; {$ENDIF}
	{ALIGN64} RemdeskVirtualChannel: BOOL;          (* 1030 *)  {$IFDEF CPU32} padding8244: UInt32; {$ENDIF}
	{ALIGN64} LyncRdpMode: BOOL;                    (* 1031 *)  {$IFDEF CPU32} padding8252: UInt32; {$ENDIF}
	padding1088: array[0..Pred(1088 - 1032)] of UInt64; (* 1032 *)

	(**
	 * X.224 Connection Request/Confirm
	 *)

	(* Protocol Security *)
	{ALIGN64} TlsSecurity: BOOL;                     (* 1088 *)  {$IFDEF CPU32} padding8708: UInt32; {$ENDIF}
	{ALIGN64} NlaSecurity: BOOL;                     (* 1089 *)  {$IFDEF CPU32} padding8716: UInt32; {$ENDIF}
	{ALIGN64} RdpSecurity: BOOL;                     (* 1090 *)  {$IFDEF CPU32} padding8724: UInt32; {$ENDIF}
	{ALIGN64} ExtSecurity: BOOL;                     (* 1091 *)  {$IFDEF CPU32} padding8732: UInt32; {$ENDIF}
	{ALIGN64} Authentication: BOOL;                  (* 1092 *)  {$IFDEF CPU32} padding8740: UInt32; {$ENDIF}
	{ALIGN64} RequestedProtocols: UINT32;            (* 1093 *)  {$IFDEF CPU32} padding8748: UInt32; {$ENDIF}
	{ALIGN64} SelectedProtocol: UINT32;              (* 1094 *)  {$IFDEF CPU32} padding8756: UInt32; {$ENDIF}
	{ALIGN64} NegotiationFlags: UINT32;              (* 1095 *)  {$IFDEF CPU32} padding8764: UInt32; {$ENDIF}
	{ALIGN64} NegotiateSecurityLayer: BOOL;          (* 1096 *)  {$IFDEF CPU32} padding8772: UInt32; {$ENDIF}
	{ALIGN64} RestrictedAdminModeRequired: BOOL;     (* 1097 *)  {$IFDEF CPU32} padding8780: UInt32; {$ENDIF}
	{ALIGN64} AuthenticationServiceClass: PAnsiChar; (* 1098 *)  {$IFDEF CPU32} padding8788: UInt32; {$ENDIF}
	{ALIGN64} DisableCredentialsDelegation: BOOL;    (* 1099 *)  {$IFDEF CPU32} padding8796: UInt32; {$ENDIF}
	{ALIGN64} AuthenticationLevel: UINT32;           (* 1100 *)  {$IFDEF CPU32} padding8804: UInt32; {$ENDIF}
	{ALIGN64} AllowedTlsCiphers: PAnsiChar;          (* 1101 *)  {$IFDEF CPU32} padding8812: UInt32; {$ENDIF}
	{ALIGN64} VmConnectMode: BOOL;                   (* 1102 *)  {$IFDEF CPU32} padding8820: UInt32; {$ENDIF}
	{ALIGN64} NtlmSamFile: PAnsiChar;                (* 1103 *)  {$IFDEF CPU32} padding8828: UInt32; {$ENDIF}
	{ALIGN64} FIPSMode: BOOL;                        (* 1104 *)  {$IFDEF CPU32} padding8836: UInt32; {$ENDIF}
	{ALIGN64} TlsSecLevel: UINT32;                   (* 1105 *)  {$IFDEF CPU32} padding8844: UInt32; {$ENDIF}
	padding1152: array[0..Pred(1152 - 1106)] of UInt64; (* 1106 *)

	(* Connection Cookie *)
	{ALIGN64} MstscCookieMode: BOOL;         (* 1152 *)  {$IFDEF CPU32} padding9220: UInt32; {$ENDIF}
	{ALIGN64} CookieMaxLength: UINT32;       (* 1153 *)  {$IFDEF CPU32} padding9228: UInt32; {$ENDIF}
	{ALIGN64} PreconnectionId: UINT32;       (* 1154 *)  {$IFDEF CPU32} padding9236: UInt32; {$ENDIF}
	{ALIGN64} PreconnectionBlob: PAnsiChar;  (* 1155 *)  {$IFDEF CPU32} padding9244: UInt32; {$ENDIF}
	{ALIGN64} SendPreconnectionPdu: BOOL;    (* 1156 *)  {$IFDEF CPU32} padding9252: UInt32; {$ENDIF}
	padding1216: array[0..Pred(1216 - 1157)] of UInt64; (* 1157 *)

	(* Server Redirection *)
	{ALIGN64} RedirectionFlags: UINT32;                (* 1216 *)  {$IFDEF CPU32} padding9732: UInt32; {$ENDIF}
	{ALIGN64} TargetNetAddress: PAnsiChar;             (* 1217 *)  {$IFDEF CPU32} padding9740: UInt32; {$ENDIF}
	{ALIGN64} LoadBalanceInfo: PByte;                  (* 1218 *)  {$IFDEF CPU32} padding9748: UInt32; {$ENDIF}
	{ALIGN64} LoadBalanceInfoLength: UINT32;           (* 1219 *)  {$IFDEF CPU32} padding9756: UInt32; {$ENDIF}
	{ALIGN64} RedirectionUsername: PAnsiChar;          (* 1220 *)  {$IFDEF CPU32} padding9764: UInt32; {$ENDIF}
	{ALIGN64} RedirectionDomain: PAnsiChar;            (* 1221 *)  {$IFDEF CPU32} padding9772: UInt32; {$ENDIF}
	{ALIGN64} RedirectionPassword: PByte;              (* 1222 *)  {$IFDEF CPU32} padding9780: UInt32; {$ENDIF}
	{ALIGN64} RedirectionPasswordLength: UINT32;       (* 1223 *)  {$IFDEF CPU32} padding9788: UInt32; {$ENDIF}
	{ALIGN64} RedirectionTargetFQDN: PAnsiChar;        (* 1224 *)  {$IFDEF CPU32} padding9796: UInt32; {$ENDIF}
	{ALIGN64} RedirectionTargetNetBiosName: PAnsiChar; (* 1225 *)  {$IFDEF CPU32} padding9804: UInt32; {$ENDIF}
	{ALIGN64} RedirectionTsvUrl: PByte;                (* 1226 *)  {$IFDEF CPU32} padding9812: UInt32; {$ENDIF}
	{ALIGN64} RedirectionTsvUrlLength: UINT32;         (* 1227 *)  {$IFDEF CPU32} padding9820: UInt32; {$ENDIF}
	{ALIGN64} TargetNetAddressCount: UINT32;           (* 1228 *)  {$IFDEF CPU32} padding9828: UInt32; {$ENDIF}
	{ALIGN64} TargetNetAddresses: PPAnsiChar;          (* 1229 *)  {$IFDEF CPU32} padding9836: UInt32; {$ENDIF}
	{ALIGN64} TargetNetPorts: PUINT32;                 (* 1230 *)  {$IFDEF CPU32} padding9844: UInt32; {$ENDIF}
	{ALIGN64} RedirectionAcceptedCert: PAnsiChar;      (* 1231 *)  {$IFDEF CPU32} padding9852: UInt32; {$ENDIF}
	{ALIGN64} RedirectionAcceptedCertLength: UINT32;   (* 1232 *)  {$IFDEF CPU32} padding9860: UInt32; {$ENDIF}
	{ALIGN64} RedirectionPreferType: UINT32;           (* 1233 *)  {$IFDEF CPU32} padding9868: UInt32; {$ENDIF}
	padding1280: array[0..Pred(1280 - 1234)] of UInt64; (* 1234 *)

	(**
	 * Security
	 *)

	(* Credentials Cache *)
	{ALIGN64} Password51: PByte;          (* 1280 *)  {$IFDEF CPU32} padding10244: UInt32; {$ENDIF}
	{ALIGN64} Password51Length: UINT32;   (* 1281 *)  {$IFDEF CPU32} padding10252: UInt32; {$ENDIF}
	{ALIGN64} SmartcardLogon: BOOL;       (* 1282 *)  {$IFDEF CPU32} padding10260: UInt32; {$ENDIF}
	{ALIGN64} PromptForCredentials: BOOL; (* 1283 *)  {$IFDEF CPU32} padding10268: UInt32; {$ENDIF}
  padding1344: array[0..Pred(1344 - 1284)] of UInt64;    (* 1284 *)

	(* Kerberos Authentication *)
	{ALIGN64} KerberosKdc: PAnsiChar;   (* 1344 *)  {$IFDEF CPU32} padding10756: UInt32; {$ENDIF}
	{ALIGN64} KerberosRealm: PAnsiChar; (* 1345 *)  {$IFDEF CPU32} padding10764: UInt32; {$ENDIF}
	padding1408: array[0..Pred(1408 - 1346)] of UInt64; (* 1346 *)

	(* Server Certificate *)
	{ALIGN64} IgnoreCertificate: BOOL;               (* 1408 *)  {$IFDEF CPU32} padding11268: UInt32; {$ENDIF}
	{ALIGN64} CertificateName: PAnsiChar;            (* 1409 *)  {$IFDEF CPU32} padding11276: UInt32; {$ENDIF}
	{ALIGN64} CertificateFile: PAnsiChar;            (* 1410 *)  {$IFDEF CPU32} padding11284: UInt32; {$ENDIF}
	{ALIGN64} PrivateKeyFile: PAnsiChar;             (* 1411 *)  {$IFDEF CPU32} padding11292: UInt32; {$ENDIF}
	{ALIGN64} RdpKeyFile: PAnsiChar;                 (* 1412 *)  {$IFDEF CPU32} padding11300: UInt32; {$ENDIF}
	{ALIGN64} RdpServerRsaKey: Pointer;              (* 1413 *)  {$IFDEF CPU32} padding11308: UInt32; {$ENDIF}
	{ALIGN64} RdpServerCertificate: Pointer;         (* 1414 *)  {$IFDEF CPU32} padding11316: UInt32; {$ENDIF}
	{ALIGN64} ExternalCertificateManagement: BOOL;   (* 1415 *)  {$IFDEF CPU32} padding11324: UInt32; {$ENDIF}
	{ALIGN64} CertificateContent: PAnsiChar;         (* 1416 *)  {$IFDEF CPU32} padding11332: UInt32; {$ENDIF}
	{ALIGN64} PrivateKeyContent: PAnsiChar;          (* 1417 *)  {$IFDEF CPU32} padding11340: UInt32; {$ENDIF}
	{ALIGN64} RdpKeyContent: PAnsiChar;              (* 1418 *)  {$IFDEF CPU32} padding11348: UInt32; {$ENDIF}
	{ALIGN64} AutoAcceptCertificate: BOOL;           (* 1419 *)  {$IFDEF CPU32} padding11356: UInt32; {$ENDIF}
	{ALIGN64} AutoDenyCertificate: BOOL;             (* 1420 *)  {$IFDEF CPU32} padding11364: UInt32; {$ENDIF}
	padding1472: array[0..Pred(1472 - 1421)] of UInt64; (* 1421 *)
	padding1536: array[0..Pred(1536 - 1472)] of UInt64; (* 1472 *)

	(**
	 * User Interface
	 *)

	(* Window Settings *)
	{ALIGN64} Workarea: BOOL;                (* 1536 *)  {$IFDEF CPU32} padding12292: UInt32; {$ENDIF}
	{ALIGN64} Fullscreen: BOOL;              (* 1537 *)  {$IFDEF CPU32} padding12300: UInt32; {$ENDIF}
	{ALIGN64} PercentScreen: UINT32;         (* 1538 *)  {$IFDEF CPU32} padding12308: UInt32; {$ENDIF}
	{ALIGN64} GrabKeyboard: BOOL;            (* 1539 *)  {$IFDEF CPU32} padding12316: UInt32; {$ENDIF}
	{ALIGN64} Decorations: BOOL;             (* 1540 *)  {$IFDEF CPU32} padding12324: UInt32; {$ENDIF}
	{ALIGN64} MouseMotion: BOOL;             (* 1541 *)  {$IFDEF CPU32} padding12332: UInt32; {$ENDIF}
	{ALIGN64} WindowTitle: PAnsiChar;        (* 1542 *)  {$IFDEF CPU32} padding12340: UInt32; {$ENDIF}
	{ALIGN64} ParentWindowId: UINT64;        (* 1543 *)                         //48
	{ALIGN64} AsyncInput: BOOL;              (* 1544 *)  {$IFDEF CPU32} padding12356: UInt32; {$ENDIF}
	{ALIGN64} AsyncUpdate: BOOL;             (* 1545 *)  {$IFDEF CPU32} padding12364: UInt32; {$ENDIF}
	{ALIGN64} AsyncChannels: BOOL;           (* 1546 *)  {$IFDEF CPU32} padding12372: UInt32; {$ENDIF}
	padding1548_: array[0..Pred(1548 - 1547)] of UInt64; (* 1547 *)

	{ALIGN64} ToggleFullscreen: BOOL;        (* 1548 *)  {$IFDEF CPU32} padding12388: UInt32; {$ENDIF}
	{ALIGN64} WmClass: PAnsiChar;            (* 1549 *)  {$IFDEF CPU32} padding12396: UInt32; {$ENDIF}
	{ALIGN64} EmbeddedWindow: BOOL;          (* 1550 *)  {$IFDEF CPU32} padding12404: UInt32; {$ENDIF}
	{ALIGN64} SmartSizing: BOOL;             (* 1551 *)  {$IFDEF CPU32} padding12412: UInt32; {$ENDIF}
	{ALIGN64} XPan: INT32;                   (* 1552 *)  {$IFDEF CPU32} padding12420: UInt32; {$ENDIF}
	{ALIGN64} YPan: INT32;                   (* 1553 *)  {$IFDEF CPU32} padding12428: UInt32; {$ENDIF}
	{ALIGN64} SmartSizingWidth: UINT32;      (* 1554 *)  {$IFDEF CPU32} padding12436: UInt32; {$ENDIF}
	{ALIGN64} SmartSizingHeight: UINT32;     (* 1555 *)  {$IFDEF CPU32} padding12444: UInt32; {$ENDIF}
	{ALIGN64} PercentScreenUseWidth: BOOL;   (* 1556 *)  {$IFDEF CPU32} padding12452: UInt32; {$ENDIF}
	{ALIGN64} PercentScreenUseHeight: BOOL;  (* 1557 *)  {$IFDEF CPU32} padding12460: UInt32; {$ENDIF}
	{ALIGN64} DynamicResolutionUpdate: BOOL; (* 1558 *)  {$IFDEF CPU32} padding12468: UInt32; {$ENDIF}
	padding1601: array[0..Pred(1601 - 1559)] of UInt64; (* 1559 *)

	(* Miscellaneous *)
	{ALIGN64} SoftwareGdi: BOOL;          (* 1601 *)  {$IFDEF CPU32} padding12812: UInt32; {$ENDIF}
	{ALIGN64} LocalConnection: BOOL;      (* 1602 *)  {$IFDEF CPU32} padding12820: UInt32; {$ENDIF}
	{ALIGN64} AuthenticationOnly: BOOL;   (* 1603 *)  {$IFDEF CPU32} padding12828: UInt32; {$ENDIF}
	{ALIGN64} CredentialsFromStdin: BOOL; (* 1604 *)  {$IFDEF CPU32} padding12836: UInt32; {$ENDIF}
	{ALIGN64} UnmapButtons: BOOL;         (* 1605 *)  {$IFDEF CPU32} padding12844: UInt32; {$ENDIF}
	{ALIGN64} OldLicenseBehaviour: BOOL;  (* 1606 *)  {$IFDEF CPU32} padding12852: UInt32; {$ENDIF}
	padding1664: array[0..Pred(1664 - 1607)] of UInt64;   (* 1607 *)

	(* Names *)
	{ALIGN64} ComputerName: PAnsiChar; (* 1664 *)
	padding1728: array[0..Pred(1728 - 1665)] of UInt64; (* 1665 *)

	(* Files *)
	{ALIGN64} ConnectionFile: PAnsiChar; (* 1728 *)  {$IFDEF CPU32} padding13828: UInt32; {$ENDIF}
	{ALIGN64} AssistanceFile: PAnsiChar; (* 1729 *)  {$IFDEF CPU32} padding13836: UInt32; {$ENDIF}
	padding1792: array[0..Pred(1792 - 1730)] of UInt64; (* 1730 *)

	(* Paths *)
	{ALIGN64} HomePath: PAnsiChar;    (* 1792 *)  {$IFDEF CPU32} padding14340: UInt32; {$ENDIF}
	{ALIGN64} ConfigPath: PAnsiChar;  (* 1793 *)  {$IFDEF CPU32} padding14348: UInt32; {$ENDIF}
	{ALIGN64} CurrentPath: PAnsiChar; (* 1794 *)  {$IFDEF CPU32} padding14356: UInt32; {$ENDIF}
	padding1856: array[0..Pred(1856 - 1795)] of UInt64; (* 1795 *)

	(* Recording *)
	{ALIGN64} DumpRemoteFx: BOOL;            (* 1856 *)  {$IFDEF CPU32} padding14852: UInt32; {$ENDIF}
	{ALIGN64} PlayRemoteFx: BOOL;            (* 1857 *)  {$IFDEF CPU32} padding14860: UInt32; {$ENDIF}
	{ALIGN64} DumpRemoteFxFile: PAnsiChar;   (* 1858 *)  {$IFDEF CPU32} padding14868: UInt32; {$ENDIF}
	{ALIGN64} PlayRemoteFxFile: PAnsiChar;   (* 1859 *)  {$IFDEF CPU32} padding14876: UInt32; {$ENDIF}
	padding1920: array[0..Pred(1920 - 1860)] of UInt64; (* 1860 *)
	padding1984: array[0..Pred(1984 - 1920)] of UInt64; (* 1920 *)

	(**
	 * Gateway
	 *)

	(* Gateway *)
	{ALIGN64} GatewayUsageMethod: UINT32;        (* 1984 *)  {$IFDEF CPU32} padding15876: UInt32; {$ENDIF}
	{ALIGN64} GatewayPort: UINT32;               (* 1985 *)  {$IFDEF CPU32} padding15884: UInt32; {$ENDIF}
	{ALIGN64} GatewayHostname: PAnsiChar;        (* 1986 *)  {$IFDEF CPU32} padding15892: UInt32; {$ENDIF}
	{ALIGN64} GatewayUsername: PAnsiChar;        (* 1987 *)  {$IFDEF CPU32} padding15900: UInt32; {$ENDIF}
	{ALIGN64} GatewayPassword: PAnsiChar;        (* 1988 *)  {$IFDEF CPU32} padding15908: UInt32; {$ENDIF}
	{ALIGN64} GatewayDomain: PAnsiChar;          (* 1989 *)  {$IFDEF CPU32} padding15916: UInt32; {$ENDIF}
	{ALIGN64} GatewayCredentialsSource: UINT32;  (* 1990 *)  {$IFDEF CPU32} padding15924: UInt32; {$ENDIF}
	{ALIGN64} GatewayUseSameCredentials: BOOL;   (* 1991 *)  {$IFDEF CPU32} padding15932: UInt32; {$ENDIF}
	{ALIGN64} GatewayEnabled: BOOL;              (* 1992 *)  {$IFDEF CPU32} padding15940: UInt32; {$ENDIF}
	{ALIGN64} GatewayBypassLocal: BOOL;          (* 1993 *)  {$IFDEF CPU32} padding15948: UInt32; {$ENDIF}
	{ALIGN64} GatewayRpcTransport: BOOL;         (* 1994 *)  {$IFDEF CPU32} padding15956: UInt32; {$ENDIF}
	{ALIGN64} GatewayHttpTransport: BOOL;        (* 1995 *)  {$IFDEF CPU32} padding15964: UInt32; {$ENDIF}
	{ALIGN64} GatewayUdpTransport: BOOL;         (* 1996 *)  {$IFDEF CPU32} padding15972: UInt32; {$ENDIF}
	{ALIGN64} GatewayAccessToken: PAnsiChar;     (* 1997 *)  {$IFDEF CPU32} padding15980: UInt32; {$ENDIF}
	{ALIGN64} GatewayAcceptedCert: PAnsiChar;    (* 1998 *)  {$IFDEF CPU32} padding15988: UInt32; {$ENDIF}
	{ALIGN64} GatewayAcceptedCertLength: UINT32; (* 1999 *)  {$IFDEF CPU32} padding15996: UInt32; {$ENDIF}
	padding2015: array[0..Pred(2015 - 2000)] of UInt64; (* 2000 *)

	(* Proxy *)
	{ALIGN64} ProxyType: UINT32;        	 (* 2015 *)  {$IFDEF CPU32} padding16124: UInt32; {$ENDIF}
	{ALIGN64} ProxyHostname: PAnsiChar;	   (* 2016 *)  {$IFDEF CPU32} padding16132: UInt32; {$ENDIF}
	{ALIGN64} ProxyPort: UINT16;	         (* 2017 *)  {$IFDEF CPU32} padding16138: UInt16; {$ENDIF}
                                                     {$IFDEF CPU32} padding16140: UInt32; {$ENDIF}
	{ALIGN64} ProxyUsername: PAnsiChar;    (* 2018 *)  {$IFDEF CPU32} padding16148: UInt32; {$ENDIF}
	{ALIGN64} ProxyPassword: PAnsiChar;    (* 2019 *)  {$IFDEF CPU32} padding16156: UInt32; {$ENDIF}
	padding2112: array[0..Pred(2112 - 2020)] of UInt64; (* 2020 *)

	(**
	 * RemoteApp
	 *)

	(* RemoteApp *)
	{ALIGN64} RemoteApplicationMode: BOOL;               (* 2112 *)  {$IFDEF CPU32} padding16900: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationName: PAnsiChar;          (* 2113 *)  {$IFDEF CPU32} padding16908: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationIcon: PAnsiChar;          (* 2114 *)  {$IFDEF CPU32} padding16916: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationProgram: PAnsiChar;       (* 2115 *)  {$IFDEF CPU32} padding16924: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationFile: PAnsiChar;          (* 2116 *)  {$IFDEF CPU32} padding16932: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationGuid: PAnsiChar;          (* 2117 *)  {$IFDEF CPU32} padding16940: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationCmdLine: PAnsiChar;       (* 2118 *)  {$IFDEF CPU32} padding16948: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationExpandCmdLine: UINT32;    (* 2119 *)  {$IFDEF CPU32} padding16956: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationExpandWorkingDir: UINT32; (* 2120 *)  {$IFDEF CPU32} padding16964: UInt32; {$ENDIF}
	{ALIGN64} DisableRemoteAppCapsCheck: BOOL;           (* 2121 *)  {$IFDEF CPU32} padding16972: UInt32; {$ENDIF}
	{ALIGN64} RemoteAppNumIconCaches: UINT32;            (* 2122 *)  {$IFDEF CPU32} padding16980: UInt32; {$ENDIF}
	{ALIGN64} RemoteAppNumIconCacheEntries: UINT32;      (* 2123 *)  {$IFDEF CPU32} padding16988: UInt32; {$ENDIF}
	{ALIGN64} RemoteAppLanguageBarSupported: BOOL;       (* 2124 *)  {$IFDEF CPU32} padding16996: UInt32; {$ENDIF}
	{ALIGN64} RemoteWndSupportLevel: UINT32;             (* 2125 *)  {$IFDEF CPU32} padding17004: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationSupportLevel: UINT32;     (* 2126 *)  {$IFDEF CPU32} padding17012: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationSupportMask: UINT32;      (* 2127 *)  {$IFDEF CPU32} padding17020: UInt32; {$ENDIF}
	{ALIGN64} RemoteApplicationWorkingDir: PAnsiChar;    (* 2128 *)  {$IFDEF CPU32} padding17028: UInt32; {$ENDIF}
	padding2176: array[0..Pred(2176 - 2129)] of UInt64; (* 2129 *)
	padding2240: array[0..Pred(2240 - 2176)] of UInt64; (* 2176 *)

	(**
	 * Mandatory Capabilities
	 *)

	(* Capabilities *)
	{ALIGN64} ReceivedCapabilities: PByte;      (* 2240 *)  {$IFDEF CPU32} padding17924: UInt32; {$ENDIF}
	{ALIGN64} ReceivedCapabilitiesSize: UINT32; (* 2241 *)  {$IFDEF CPU32} padding17932: UInt32; {$ENDIF}
	padding2304: array[0..Pred(2304 - 2242)] of UInt64; (* 2242 *)

	(* General Capabilities *)
	{ALIGN64} OsMajorType: UINT32;             (* 2304 *)  {$IFDEF CPU32} padding18436: UInt32; {$ENDIF}
	{ALIGN64} OsMinorType: UINT32;             (* 2305 *)  {$IFDEF CPU32} padding18444: UInt32; {$ENDIF}
	{ALIGN64} RefreshRect: BOOL;               (* 2306 *)  {$IFDEF CPU32} padding18452: UInt32; {$ENDIF}
	{ALIGN64} SuppressOutput: BOOL;            (* 2307 *)  {$IFDEF CPU32} padding18460: UInt32; {$ENDIF}
	{ALIGN64} FastPathOutput: BOOL;            (* 2308 *)  {$IFDEF CPU32} padding18468: UInt32; {$ENDIF}
	{ALIGN64} SaltedChecksum: BOOL;            (* 2309 *)  {$IFDEF CPU32} padding18476: UInt32; {$ENDIF}
	{ALIGN64} LongCredentialsSupported: BOOL;  (* 2310 *)  {$IFDEF CPU32} padding18484: UInt32; {$ENDIF}
	{ALIGN64} NoBitmapCompressionHeader: BOOL; (* 2311 *)  {$IFDEF CPU32} padding18492: UInt32; {$ENDIF}
	{ALIGN64} BitmapCompressionDisabled: BOOL; (* 2312 *)  {$IFDEF CPU32} padding18500: UInt32; {$ENDIF}
	padding2368: array[0..Pred(2368 - 2313)] of UInt64; (* 2313 *)

	(* Bitmap Capabilities *)
	{ALIGN64} DesktopResize: BOOL;                 (* 2368 *)  {$IFDEF CPU32} padding18948: UInt32; {$ENDIF}
	{ALIGN64} DrawAllowDynamicColorFidelity: BOOL; (* 2369 *)  {$IFDEF CPU32} padding18956: UInt32; {$ENDIF}
	{ALIGN64} DrawAllowColorSubsampling: BOOL;     (* 2370 *)  {$IFDEF CPU32} padding18964: UInt32; {$ENDIF}
	{ALIGN64} DrawAllowSkipAlpha: BOOL;            (* 2371 *)  {$IFDEF CPU32} padding18972: UInt32; {$ENDIF}
	padding2432: array[0..Pred(2432 - 2372)] of UInt64; (* 2372 *)

	(* Order Capabilities *)
	{ALIGN64} OrderSupport: PByte;                   (* 2432 *)  {$IFDEF CPU32} padding19460: UInt32; {$ENDIF}
	{ALIGN64} BitmapCacheV3Enabled: BOOL;            (* 2433 *)  {$IFDEF CPU32} padding19468: UInt32; {$ENDIF}
	{ALIGN64} AltSecFrameMarkerSupport: BOOL;        (* 2434 *)  {$IFDEF CPU32} padding19476: UInt32; {$ENDIF}
	{ALIGN64} AllowUnanouncedOrdersFromServer: BOOL; (* 2435 *)  {$IFDEF CPU32} padding19484: UInt32; {$ENDIF}
	padding2497: array[0..Pred(2497 - 2436)] of UInt64; (* 2436 *)

	(* Bitmap Cache Capabilities *)
	{ALIGN64} BitmapCacheEnabled: BOOL;         (* 2497 *)  {$IFDEF CPU32} padding19980: UInt32; {$ENDIF}
	{ALIGN64} BitmapCacheVersion: UINT32;       (* 2498 *)  {$IFDEF CPU32} padding19988: UInt32; {$ENDIF}
	{ALIGN64} AllowCacheWaitingList: BOOL;      (* 2499 *)  {$IFDEF CPU32} padding19996: UInt32; {$ENDIF}
	{ALIGN64} BitmapCachePersistEnabled: BOOL;  (* 2500 *)  {$IFDEF CPU32} padding20004: UInt32; {$ENDIF}
	{ALIGN64} BitmapCacheV2NumCells: UINT32;    (* 2501 *)  {$IFDEF CPU32} padding20012: UInt32; {$ENDIF}
	{ALIGN64} BitmapCacheV2CellInfo: Pointer;   (* 2502 *)  {$IFDEF CPU32} padding20020: UInt32; {$ENDIF}
	padding2560: array[0..Pred(2560 - 2503)] of UInt64; (* 2503 *)

	(* Pointer Capabilities *)
	{ALIGN64} ColorPointerFlag: BOOL;    (* 2560 *)  {$IFDEF CPU32} padding20484: UInt32; {$ENDIF}
	{ALIGN64} PointerCacheSize: UINT32;  (* 2561 *)  {$IFDEF CPU32} padding20492: UInt32; {$ENDIF}
	padding2624: array[0..Pred(2624 - 2562)] of UInt64; (* 2562 *)

	(* Input Capabilities *)
	{ALIGN64} KeyboardLayout: UINT32;       (* 2624 *)  {$IFDEF CPU32} padding20996: UInt32; {$ENDIF}
	{ALIGN64} KeyboardType: UINT32;         (* 2625 *)  {$IFDEF CPU32} padding21004: UInt32; {$ENDIF}
	{ALIGN64} KeyboardSubType: UINT32;      (* 2626 *)  {$IFDEF CPU32} padding21012: UInt32; {$ENDIF}
	{ALIGN64} KeyboardFunctionKey: UINT32;  (* 2627 *)  {$IFDEF CPU32} padding21020: UInt32; {$ENDIF}
	{ALIGN64} ImeFileName: PAnsiChar;       (* 2628 *)  {$IFDEF CPU32} padding21028: UInt32; {$ENDIF}
	{ALIGN64} UnicodeInput: BOOL;           (* 2629 *)  {$IFDEF CPU32} padding21036: UInt32; {$ENDIF}
	{ALIGN64} FastPathInput: BOOL;          (* 2630 *)  {$IFDEF CPU32} padding21044: UInt32; {$ENDIF}
	{ALIGN64} MultiTouchInput: BOOL;        (* 2631 *)  {$IFDEF CPU32} padding21052: UInt32; {$ENDIF}
	{ALIGN64} MultiTouchGestures: BOOL;     (* 2632 *)  {$IFDEF CPU32} padding21060: UInt32; {$ENDIF}
	{ALIGN64} KeyboardHook: UINT32;         (* 2633 *)  {$IFDEF CPU32} padding21068: UInt32; {$ENDIF}
	{ALIGN64} HasHorizontalWheel: BOOL;     (* 2634 *)  {$IFDEF CPU32} padding21076: UInt32; {$ENDIF}
	{ALIGN64} HasExtendedMouseEvent: BOOL;  (* 2635 *)  {$IFDEF CPU32} padding21084: UInt32; {$ENDIF}
	padding2688: array[0..Pred(2688 - 2636)] of UInt64; (* 2636 *)

	(* Brush Capabilities *)
	{ALIGN64} BrushSupportLevel: UINT32;  (* 2688 *)
	padding2752: array[0..Pred(2752 - 2689)] of UInt64; (* 2689 *)

	(* Glyph Cache Capabilities *)
	{ALIGN64} GlyphSupportLevel: UINT32;   (* 2752 *)  {$IFDEF CPU32} padding22020: UInt32; {$ENDIF}
	{ALIGN64} GlyphCache: Pointer;         (* 2753 *)  {$IFDEF CPU32} padding22028: UInt32; {$ENDIF}
	{ALIGN64} FragCache: Pointer;          (* 2754 *)  {$IFDEF CPU32} padding22036: UInt32; {$ENDIF}
	padding2816: array[0..Pred(2816 - 2755)] of UInt64; (* 2755 *)

	(* Offscreen Bitmap Cache *)
	{ALIGN64} OffscreenSupportLevel: UINT32;  (* 2816 *)  {$IFDEF CPU32} padding22532: UInt32; {$ENDIF}
	{ALIGN64} OffscreenCacheSize: UINT32;     (* 2817 *)  {$IFDEF CPU32} padding22540: UInt32; {$ENDIF}
	{ALIGN64} OffscreenCacheEntries: UINT32;  (* 2818 *)  {$IFDEF CPU32} padding22548: UInt32; {$ENDIF}
	padding2880: array[0..Pred(2880 - 2819)] of UInt64; (* 2819 *)

	(* Virtual Channel Capabilities *)
	{ALIGN64} VirtualChannelCompressionFlags: UINT32; (* 2880 *)  {$IFDEF CPU32} padding23044: UInt32; {$ENDIF}
	{ALIGN64} VirtualChannelChunkSize: UINT32;        (* 2881 *)  {$IFDEF CPU32} padding23052: UInt32; {$ENDIF}
	padding2944: array[0..Pred(2944 - 2882)] of UInt64; (* 2882 *)

	(* Sound Capabilities *)
	{ALIGN64} SoundBeepsEnabled: BOOL; (* 2944 *)  {$IFDEF CPU32} padding23556: UInt32; {$ENDIF}
	padding3008: array[0..Pred(3008 - 2945)] of UInt64; (* 2945 *)
	padding3072: array[0..Pred(3072 - 3008)] of UInt64; (* 3008 *)

	(**
	 * Optional Capabilities
	 *)

	(* Bitmap Cache Host Capabilities *)
	padding3136: array[0..Pred(3136 - 3072)] of UInt64; (* 3072 *)

	(* Control Capabilities *)
	padding3200: array[0..Pred(3200 - 3136)] of UInt64; (* 3136 *)

	(* Window Activation Capabilities *)
	padding3264: array[0..Pred(3264 - 3200)] of UInt64; (* 3200 *)

	(* Font Capabilities *)
	padding3328: array[0..Pred(3328 - 3264)] of UInt64; (* 3264 *)

	(* Multifragment Update Capabilities *)
	{ALIGN64} MultifragMaxRequestSize: UINT32; (* 3328 *)  {$IFDEF CPU32} padding26628: UInt32; {$ENDIF}
	padding3392: array[0..Pred(3392 - 3329)] of UInt64; (* 3329 *)

	(* Large Pointer Update Capabilities *)
	{ALIGN64} LargePointerFlag: UINT32; (* 3392 *)  {$IFDEF CPU32} padding27140: UInt32; {$ENDIF}
	padding3456: array[0..Pred(3456 - 3393)] of UInt64; (* 3393 *)

	(* Desktop Composition Capabilities *)
	{ALIGN64} CompDeskSupportLevel: UINT32; (* 3456 *)  {$IFDEF CPU32} padding27652: UInt32; {$ENDIF}
	padding3520: array[0..Pred(3520 - 3457)] of UInt64; (* 3457 *)

	(* Surface Commands Capabilities *)
	{ALIGN64} SurfaceCommandsEnabled: BOOL;     (* 3520 *)  {$IFDEF CPU32} padding28164: UInt32; {$ENDIF}
	{ALIGN64} FrameMarkerCommandEnabled: BOOL;  (* 3521 *)  {$IFDEF CPU32} padding28172: UInt32; {$ENDIF}
	{ALIGN64} urfaceFrameMarkerEnabled: BOOL;   (* 3522 *)  {$IFDEF CPU32} padding28180: UInt32; {$ENDIF}
	padding3584: array[0..Pred(3584 - 3523)] of UInt64; (* 3523 *)
	padding3648: array[0..Pred(3648 - 3584)] of UInt64; (* 3584 *)

	(*
	 * Bitmap Codecs Capabilities
	 *)

	(* RemoteFX *)
	{ALIGN64} RemoteFxOnly: BOOL;            (* 3648 *)  {$IFDEF CPU32} padding29188: UInt32; {$ENDIF}
	{ALIGN64} RemoteFxCodec: BOOL;           (* 3649 *)  {$IFDEF CPU32} padding29196: UInt32; {$ENDIF}
	{ALIGN64} RemoteFxCodecId: UINT32;       (* 3650 *)  {$IFDEF CPU32} padding29204: UInt32; {$ENDIF}
	{ALIGN64} RemoteFxCodecMode: UINT32;     (* 3651 *)  {$IFDEF CPU32} padding29212: UInt32; {$ENDIF}
	{ALIGN64} RemoteFxImageCodec: BOOL;      (* 3652 *)  {$IFDEF CPU32} padding29220: UInt32; {$ENDIF}
	{ALIGN64} RemoteFxCaptureFlags: UINT32;  (* 3653 *)  {$IFDEF CPU32} padding29228: UInt32; {$ENDIF}
	padding3712: array[0..Pred(3712 - 3654)] of UInt64; (* 3654 *)

	(* NSCodec *)
	{ALIGN64} NSCodec: BOOL;                           (* 3712 *)  {$IFDEF CPU32} padding29700: UInt32; {$ENDIF}
	{ALIGN64} NSCodecId: UINT32;                       (* 3713 *)  {$IFDEF CPU32} padding29708: UInt32; {$ENDIF}
	{ALIGN64} FrameAcknowledge: UINT32;                (* 3714 *)  {$IFDEF CPU32} padding29716: UInt32; {$ENDIF}
	{ALIGN64} NSCodecColorLossLevel: UINT32;           (* 3715 *)  {$IFDEF CPU32} padding29724: UInt32; {$ENDIF}
	{ALIGN64} NSCodecAllowSubsampling: BOOL;           (* 3716 *)  {$IFDEF CPU32} padding29732: UInt32; {$ENDIF}
	{ALIGN64} NSCodecAllowDynamicColorFidelity: BOOL;  (* 3717 *)  {$IFDEF CPU32} padding29740: UInt32; {$ENDIF}
	padding3776: array[0..Pred(3776 - 3718)] of UInt64; (* 3718 *)

	(* JPEG *)
	{ALIGN64} JpegCodec: BOOL;      (* 3776 *)  {$IFDEF CPU32} padding30212: UInt32; {$ENDIF}
	{ALIGN64} JpegCodecId: UINT32;  (* 3777 *)  {$IFDEF CPU32} padding30220: UInt32; {$ENDIF}
	{ALIGN64} JpegQuality: UINT32;  (* 3778 *)  {$IFDEF CPU32} padding30228: UInt32; {$ENDIF}
	padding3840: array[0..Pred(3840 - 3779)] of UInt64; (* 3779 *)

	{ALIGN64} GfxThinClient: BOOL;    (* 3840 *)  {$IFDEF CPU32} padding30724: UInt32; {$ENDIF}
	{ALIGN64} GfxSmallCache: BOOL;    (* 3841 *)  {$IFDEF CPU32} padding30732: UInt32; {$ENDIF}
	{ALIGN64} GfxProgressive: BOOL;   (* 3842 *)  {$IFDEF CPU32} padding30740: UInt32; {$ENDIF}
	{ALIGN64} GfxProgressiveV2: BOOL; (* 3843 *)  {$IFDEF CPU32} padding30748: UInt32; {$ENDIF}
	{ALIGN64} GfxH264: BOOL;          (* 3844 *)  {$IFDEF CPU32} padding30756: UInt32; {$ENDIF}
	{ALIGN64} GfxAVC444: BOOL;        (* 3845 *)  {$IFDEF CPU32} padding30764: UInt32; {$ENDIF}
	{ALIGN64} GfxSendQoeAck: BOOL;    (* 3846 *)  {$IFDEF CPU32} padding30772: UInt32; {$ENDIF}
	{ALIGN64} GfxAVC444v2: BOOL;      (* 3847 *)  {$IFDEF CPU32} padding30780: UInt32; {$ENDIF}
	{ALIGN64} GfxCapsFilter: UINT32;  (* 3848 *)  {$IFDEF CPU32} padding30788: UInt32; {$ENDIF}
	padding3904: array[0..Pred(3904 - 3849)] of UInt64; (* 3849 *)

	(**
	 * Caches
	 *)

	(* Bitmap Cache V3 *)
	{ALIGN64} BitmapCacheV3CodecId: UINT32; (* 3904 *)  {$IFDEF CPU32} padding31236: UInt32; {$ENDIF}
	padding3968: array[0..Pred(3968 - 3905)] of UInt64; (* 3905 *)

	(* Draw Nine Grid *)
	{ALIGN64} DrawNineGridEnabled: BOOL;         (* 3968 *)  {$IFDEF CPU32} padding31748: UInt32; {$ENDIF}
	{ALIGN64} DrawNineGridCacheSize: UINT32;     (* 3969 *)  {$IFDEF CPU32} padding31756: UInt32; {$ENDIF}
	{ALIGN64} DrawNineGridCacheEntries: UINT32;  (* 3970 *)  {$IFDEF CPU32} padding31764: UInt32; {$ENDIF}
	padding4032: array[0..Pred(4032 - 3971)] of UInt64; (* 3971 *)

	(* Draw GDI+ *)
	{ALIGN64} DrawGdiPlusEnabled: BOOL;      (* 4032 *)  {$IFDEF CPU32} padding32260: UInt32; {$ENDIF}
	{ALIGN64} DrawGdiPlusCacheEnabled: BOOL; (* 4033 *)  {$IFDEF CPU32} padding32268: UInt32; {$ENDIF}
	padding4096: array[0..Pred(4096 - 4034)] of UInt64; (* 4034 *)
	padding4160: array[0..Pred(4160 - 4096)] of UInt64; (* 4096 *)

	(**
	 * Device Redirection
	 *)

	(* Device Redirection *)
	{ALIGN64} DeviceRedirection: BOOL;      (* 4160 *)  {$IFDEF CPU32} padding33284: UInt32; {$ENDIF}
	{ALIGN64} DeviceCount: UINT32;          (* 4161 *)  {$IFDEF CPU32} padding33292: UInt32; {$ENDIF}
	{ALIGN64} DeviceArraySize: UINT32;      (* 4162 *)  {$IFDEF CPU32} padding33300: UInt32; {$ENDIF}
	{ALIGN64} DeviceArray: Pointer;         (* 4163 *)  {$IFDEF CPU32} padding33308: UInt32; {$ENDIF}
	padding4288: array[0..Pred(4288 - 4164)] of UInt64; (* 4164 *)

	(* Drive Redirection *)
	{ALIGN64} RedirectDrives: BOOL;         (* 4288 *)  {$IFDEF CPU32} padding34308: UInt32; {$ENDIF}
	{ALIGN64} RedirectHomeDrive: BOOL;      (* 4289 *)  {$IFDEF CPU32} padding34316: UInt32; {$ENDIF}
	{ALIGN64} DrivesToRedirect: PAnsiChar;  (* 4290 *)  {$IFDEF CPU32} padding34324: UInt32; {$ENDIF}
	padding4416: array[0..Pred(4416 - 4291)] of UInt64; (* 4291 *)

	(* Smartcard Redirection *)
	{ALIGN64} RedirectSmartCards: BOOL; (* 4416 *)  {$IFDEF CPU32} padding35332: UInt32; {$ENDIF}
	padding4544: array[0..Pred(4544 - 4417)] of UInt64; (* 4417 *)

	(* Printer Redirection *)
	{ALIGN64} RedirectPrinters: BOOL; (* 4544 *)  {$IFDEF CPU32} padding36356: UInt32; {$ENDIF}
	padding4672: array[0..Pred(4672 - 4545)] of UInt64; (* 4545 *)

	(* Serial and Parallel Port Redirection *)
	{ALIGN64} RedirectSerialPorts: BOOL;   (* 4672 *)  {$IFDEF CPU32} padding37380: UInt32; {$ENDIF}
	{ALIGN64} RedirectParallelPorts: BOOL; (* 4673 *)  {$IFDEF CPU32} padding37388: UInt32; {$ENDIF}
	{ALIGN64} PreferIPv6OverIPv4: BOOL;    (* 4674 *)  {$IFDEF CPU32} padding37396: UInt32; {$ENDIF}
	padding4800: array[0..Pred(4800 - 4675)] of UInt64; (* 4675 *)

	(**
	 * Other Redirection
	 *)

	{ALIGN64} RedirectClipboard: BOOL; (* 4800 *)  {$IFDEF CPU32} padding38404: UInt32; {$ENDIF}
	padding4928: array[0..Pred(4928 - 4801)] of UInt64; (* 4801 *)

	(**
	 * Static Virtual Channels
	 *)

	{ALIGN64} StaticChannelCount: UINT32;        (* 4928 *)  {$IFDEF CPU32} padding39428: UInt32; {$ENDIF}
	{ALIGN64} StaticChannelArraySize: UINT32;    (* 4929 *)  {$IFDEF CPU32} padding39436: UInt32; {$ENDIF}
	{ALIGN64} StaticChannelArray: Pointer;       (* 4930 *)  {$IFDEF CPU32} padding39442: UInt32; {$ENDIF}
	padding5056: array[0..Pred(5056 - 4931)] of UInt64; (* 4931 *)

	(**
	 * Dynamic Virtual Channels
	 *)

	{ALIGN64} DynamicChannelCount: UINT32;        (* 5056 *)  {$IFDEF CPU32} padding40452: UInt32; {$ENDIF}
	{ALIGN64} DynamicChannelArraySize: UINT32;    (* 5057 *)  {$IFDEF CPU32} padding40460: UInt32; {$ENDIF}
	{ALIGN64} DynamicChannelArray: Pointer;       (* 5058 *)  {$IFDEF CPU32} padding40468: UInt32; {$ENDIF}
	{ALIGN64} SupportDynamicChannels: BOOL;       (* 5059 *)  {$IFDEF CPU32} padding40476: UInt32; {$ENDIF}
	padding5184: array[0..Pred(5184 - 5060)] of uint64; (* 5060 *)

	{ALIGN64} SupportEchoChannel: BOOL;      (* 5184 *)  {$IFDEF CPU32} padding41476: UInt32; {$ENDIF}
	{ALIGN64} SupportDisplayControl: BOOL;   (* 5185 *)  {$IFDEF CPU32} padding41484: UInt32; {$ENDIF}
	{ALIGN64} SupportGeometryTracking: BOOL; (* 5186 *)  {$IFDEF CPU32} padding41492: UInt32; {$ENDIF}
	{ALIGN64} SupportSSHAgentChannel: BOOL;  (* 5187 *)  {$IFDEF CPU32} padding41500: UInt32; {$ENDIF}
	{ALIGN64} SupportVideoOptimized: BOOL;   (* 5188 *)  {$IFDEF CPU32} padding41508: UInt32; {$ENDIF}
	{ALIGN64} RDP2TCPArgs: PAnsiChar;        (* 5189 *)  {$IFDEF CPU32} padding41516: UInt32; {$ENDIF}
	padding5312: array[0..Pred(5312 - 5190)] of uint64; (* 5190 *)

	(**
	 * WARNING: End of ABI stable zone!
	 *
	 * The zone below this point is ABI unstable, and
	 * is therefore potentially subject to ABI breakage.
	 *)

	(*
	 * Extensions
	 *)

	(* Extensions *)
	{ALIGN64} num_extensions: INT32; (*  *)  {$IFDEF CPU32} padding42500: UInt32; {$ENDIF}
	{ALIGN64} extensions: array[0..Pred(16)] of rdp_ext_set; (* 4160 bytes *)

  (* byte array marking fields that have been modified from their default value *)
	{ALIGN64} SettingsModified: PByte;  {$IFDEF CPU32} padding46664: UInt32; {$ENDIF}
	{ALIGN64} ActionScript: PAnsiChar;  {$IFDEF CPU32} padding46672: UInt32; {$ENDIF}
	{ALIGN64} Floatbar: DWORD;          {$IFDEF CPU32} padding46680: UInt32; {$ENDIF}

  end;      (* 5836 x8 *)  {46688 bytes}
  rdpSettings = rdp_settings;
  TRdpSettings = rdpSettings;

{$ENDREGION} // freerdp.h


{$REGION 'mcs.h'}

const
  MCS_BASE_CHANNEL_ID = 1001;
  MCS_GLOBAL_CHANNEL_ID = 1003;

type
  MCS_Result = (
    MCS_Result_successful = 0,
    MCS_Result_domain_merging = 1,
    MCS_Result_domain_not_hierarchical = 2,
    MCS_Result_no_such_channel = 3,
    MCS_Result_no_such_domain = 4,
    MCS_Result_no_such_user = 5,
    MCS_Result_not_admitted = 6,
    MCS_Result_other_user_id = 7,
    MCS_Result_parameters_unacceptable = 8,
    MCS_Result_token_not_available = 9,
    MCS_Result_token_not_possessed = 10,
    MCS_Result_too_many_channels = 11,
    MCS_Result_too_many_tokens = 12,
    MCS_Result_too_many_users = 13,
    MCS_Result_unspecified_failure = 14,
    MCS_Result_user_rejected = 15,
    MCS_Result_enum_length = 16
  );

  DomainMCSPDU = (
    DomainMCSPDU_PlumbDomainIndication = 0,
    DomainMCSPDU_ErectDomainRequest = 1,
    DomainMCSPDU_MergeChannelsRequest = 2,
    DomainMCSPDU_MergeChannelsConfirm = 3,
    DomainMCSPDU_PurgeChannelsIndication = 4,
    DomainMCSPDU_MergeTokensRequest = 5,
    DomainMCSPDU_MergeTokensConfirm = 6,
    DomainMCSPDU_PurgeTokensIndication = 7,
    DomainMCSPDU_DisconnectProviderUltimatum = 8,
    DomainMCSPDU_RejectMCSPDUUltimatum = 9,
    DomainMCSPDU_AttachUserRequest = 10,
    DomainMCSPDU_AttachUserConfirm = 11,
    DomainMCSPDU_DetachUserRequest = 12,
    DomainMCSPDU_DetachUserIndication = 13,
    DomainMCSPDU_ChannelJoinRequest = 14,
    DomainMCSPDU_ChannelJoinConfirm = 15,
    DomainMCSPDU_ChannelLeaveRequest = 16,
    DomainMCSPDU_ChannelConveneRequest = 17,
    DomainMCSPDU_ChannelConveneConfirm = 18,
    DomainMCSPDU_ChannelDisbandRequest = 19,
    DomainMCSPDU_ChannelDisbandIndication = 20,
    DomainMCSPDU_ChannelAdmitRequest = 21,
    DomainMCSPDU_ChannelAdmitIndication = 22,
    DomainMCSPDU_ChannelExpelRequest = 23,
    DomainMCSPDU_ChannelExpelIndication = 24,
    DomainMCSPDU_SendDataRequest = 25,
    DomainMCSPDU_SendDataIndication = 26,
    DomainMCSPDU_UniformSendDataRequest = 27,
    DomainMCSPDU_UniformSendDataIndication = 28,
    DomainMCSPDU_TokenGrabRequest = 29,
    DomainMCSPDU_TokenGrabConfirm = 30,
    DomainMCSPDU_TokenInhibitRequest = 31,
    DomainMCSPDU_TokenInhibitConfirm = 32,
    DomainMCSPDU_TokenGiveRequest = 33,
    DomainMCSPDU_TokenGiveIndication = 34,
    DomainMCSPDU_TokenGiveResponse = 35,
    DomainMCSPDU_TokenGiveConfirm = 36,
    DomainMCSPDU_TokenPleaseRequest = 37,
    DomainMCSPDU_TokenPleaseConfirm = 38,
    DomainMCSPDU_TokenReleaseRequest = 39,
    DomainMCSPDU_TokenReleaseConfirm = 40,
    DomainMCSPDU_TokenTestRequest = 41,
    DomainMCSPDU_TokenTestConfirm = 42,
    DomainMCSPDU_enum_length = 43
  );

type
  DomainParameters = record
    maxChannelIds: UINT32;
    maxUserIds: UINT32;
    maxTokenIds: UINT32;
    numPriorities: UINT32;
    minThroughput: UINT32;
    maxHeight: UINT32;
    maxMCSPDUsize: UINT32;
    protocolVersion: UINT32;
  end;

  rdp_mcs_channel = record
    Name: array [0..Pred(8)] of AnsiChar;
    options: UINT32;
    ChannelId: integer;
    joined: BOOL;
    handle: pinteger;
  end;
  rdpMcsChannel = rdp_mcs_channel;
  TRdpMcsChannel = rdpMcsChannel;
  PRdpMcsChannel = ^TRdpMcsChannel;

  rdp_mcs = record
    transport: Pointer;
    settings: PRdpSettings;
    userId: UINT16;
    baseChannelId: UINT16;
    messageChannelId: UINT16;
    domainParameters: DomainParameters;
    targetParameters: DomainParameters;
    minimumParameters: DomainParameters;
    maximumParameters: DomainParameters;
    userChannelJoined: BOOL;
    globalChannelJoined: BOOL;
    messageChannelJoined: BOOL;
    channelCount: UINT32;
    channelMaxCount: UINT32;
    channels: ^TRdpMcsChannel;
  end;

const
  MCS_SEND_DATA_HEADER_MAX_LENGTH = 8;

  MCS_TYPE_CONNECT_INITIAL = $65;
  MCS_TYPE_CONNECT_RESPONSE = $66;
{$ENDREGION} // mcs.h

{$REGION 'tpkt.h'}
const
  TPKT_HEADER_LENGTH = 4;
{$ENDREGION} // tpkt.h

{$REGION 'tpdu.h'}
type
  X224_TPDU_TYPE = (
    X224_TPDU_CONNECTION_REQUEST = $E0,
    X224_TPDU_CONNECTION_CONFIRM = $D0,
    X224_TPDU_DISCONNECT_REQUEST = $80,
    X224_TPDU_DATA = $F0,
    X224_TPDU_ERROR = $70
  );

const
  TPDU_DATA_HEADER_LENGTH = 3;
  TPDU_CONNECTION_REQUEST_HEADER_LENGTH = 7;
  TPDU_CONNECTION_CONFIRM_HEADER_LENGTH = 7;
  TPDU_DISCONNECT_REQUEST_HEADER_LENGTH = 7;

  TPDU_DATA_LENGTH = (TPKT_HEADER_LENGTH + TPDU_DATA_HEADER_LENGTH);
  TPDU_CONNECTION_REQUEST_LENGTH = (TPKT_HEADER_LENGTH + TPDU_CONNECTION_REQUEST_HEADER_LENGTH);
  TPDU_CONNECTION_CONFIRM_LENGTH = (TPKT_HEADER_LENGTH + TPDU_CONNECTION_CONFIRM_HEADER_LENGTH);
  TPDU_DISCONNECT_REQUEST_LENGTH = (TPKT_HEADER_LENGTH + TPDU_DISCONNECT_REQUEST_HEADER_LENGTH);
{$ENDREGION} // tpdu.h

{$REGION 'rdp.h'}
const
  (* Security Header Flags *)
  SEC_EXCHANGE_PKT = $0001;
  SEC_TRANSPORT_REQ = $0002;
  SEC_TRANSPORT_RSP = $0004;
  SEC_ENCRYPT = $0008;
  SEC_RESET_SEQNO = $0010;
  SEC_IGNORE_SEQNO = $0020;
  SEC_INFO_PKT = $0040;
  SEC_LICENSE_PKT = $0080;
  SEC_LICENSE_ENCRYPT_CS = $0200;
  SEC_LICENSE_ENCRYPT_SC = $0200;
  SEC_REDIRECTION_PKT = $0400;
  SEC_SECURE_CHECKSUM = $0800;
  SEC_AUTODETECT_REQ = $1000;
  SEC_AUTODETECT_RSP = $2000;
  SEC_HEARTBEAT = $4000;
  SEC_FLAGSHI_VALID = $8000;

  SEC_PKT_CS_MASK = (SEC_EXCHANGE_PKT or SEC_INFO_PKT);
  SEC_PKT_SC_MASK = (SEC_LICENSE_PKT or SEC_REDIRECTION_PKT);
  SEC_PKT_MASK = (SEC_PKT_CS_MASK or SEC_PKT_SC_MASK);

  RDP_SECURITY_HEADER_LENGTH = 4;
  RDP_SHARE_CONTROL_HEADER_LENGTH = 6;
  RDP_SHARE_DATA_HEADER_LENGTH = 12;
  RDP_PACKET_HEADER_MAX_LENGTH = (TPDU_DATA_LENGTH + MCS_SEND_DATA_HEADER_MAX_LENGTH);

  PDU_TYPE_DEMAND_ACTIVE = $1;
  PDU_TYPE_CONFIRM_ACTIVE = $3;
  PDU_TYPE_DEACTIVATE_ALL = $6;
  PDU_TYPE_DATA = $7;
  PDU_TYPE_SERVER_REDIRECTION = $A;

  PDU_TYPE_FLOW_TEST = $41;
  PDU_TYPE_FLOW_RESPONSE = $42;
  PDU_TYPE_FLOW_STOP = $43;

  FINALIZE_SC_SYNCHRONIZE_PDU = $01;
  FINALIZE_SC_CONTROL_COOPERATE_PDU = $02;
  FINALIZE_SC_CONTROL_GRANTED_PDU = $04;
  FINALIZE_SC_FONT_MAP_PDU = $08;
  FINALIZE_SC_COMPLETE = $0F;

  (* Data PDU Types *)
  DATA_PDU_TYPE_UPDATE = $02;
  DATA_PDU_TYPE_CONTROL = $14;
  DATA_PDU_TYPE_POINTER = $1B;
  DATA_PDU_TYPE_INPUT = $1C;
  DATA_PDU_TYPE_SYNCHRONIZE = $1F;
  DATA_PDU_TYPE_REFRESH_RECT = $21;
  DATA_PDU_TYPE_PLAY_SOUND = $22;
  DATA_PDU_TYPE_SUPPRESS_OUTPUT = $23;
  DATA_PDU_TYPE_SHUTDOWN_REQUEST = $24;
  DATA_PDU_TYPE_SHUTDOWN_DENIED = $25;
  DATA_PDU_TYPE_SAVE_SESSION_INFO = $26;
  DATA_PDU_TYPE_FONT_LIST = $27;
  DATA_PDU_TYPE_FONT_MAP = $28;
  DATA_PDU_TYPE_SET_KEYBOARD_INDICATORS = $29;
  DATA_PDU_TYPE_BITMAP_CACHE_PERSISTENT_LIST = $2B;
  DATA_PDU_TYPE_BITMAP_CACHE_ERROR = $2C;
  DATA_PDU_TYPE_SET_KEYBOARD_IME_STATUS = $2D;
  DATA_PDU_TYPE_OFFSCREEN_CACHE_ERROR = $2E;
  DATA_PDU_TYPE_SET_ERROR_INFO = $2F;
  DATA_PDU_TYPE_DRAW_NINEGRID_ERROR = $30;
  DATA_PDU_TYPE_DRAW_GDIPLUS_ERROR = $31;
  DATA_PDU_TYPE_ARC_STATUS = $32;
  DATA_PDU_TYPE_STATUS_INFO = $36;
  DATA_PDU_TYPE_MONITOR_LAYOUT = $37;
  DATA_PDU_TYPE_FRAME_ACKNOWLEDGE = $38;

  (* Stream Identifiers *)
  STREAM_UNDEFINED = $00;
  STREAM_LOW = $01;
  STREAM_MED = $02;
  STREAM_HI = $04;
{$ENDREGION} // rdp.h

{$REGION 'settings.h'}
const
  {(* RAIL Support Level *)}
  RAIL_LEVEL_SUPPORTED                           = $00000001;
  RAIL_LEVEL_DOCKED_LANGBAR_SUPPORTED            = $00000002;
  RAIL_LEVEL_SHELL_INTEGRATION_SUPPORTED         = $00000004;
  RAIL_LEVEL_LANGUAGE_IME_SYNC_SUPPORTED         = $00000008;
  RAIL_LEVEL_SERVER_TO_CLIENT_IME_SYNC_SUPPORTED = $00000010;
  RAIL_LEVEL_HIDE_MINIMIZED_APPS_SUPPORTED       = $00000020;
  RAIL_LEVEL_WINDOW_CLOAKING_SUPPORTED           = $00000040;
  RAIL_LEVEL_HANDSHAKE_EX_SUPPORTED              = $00000080;

  {(* Performance Flags *)}
  PERF_FLAG_NONE                  	= $00000000;
  PERF_DISABLE_WALLPAPER          	= $00000001;
  PERF_DISABLE_FULLWINDOWDRAG    		= $00000002;
  PERF_DISABLE_MENUANIMATIONS     	= $00000004;
  PERF_DISABLE_THEMING            	= $00000008;
  PERF_DISABLE_CURSOR_SHADOW      	= $00000020;
  PERF_DISABLE_CURSORSETTINGS     	= $00000040;
  PERF_ENABLE_FONT_SMOOTHING      	= $00000080;
  PERF_ENABLE_DESKTOP_COMPOSITION 	= $00000100;

  {(* Connection Types *)}
  CONNECTION_TYPE_MODEM			     = $01;
  CONNECTION_TYPE_BROADBAND_LOW	 = $02;
  CONNECTION_TYPE_SATELLITE		   = $03;
  CONNECTION_TYPE_BROADBAND_HIGH = $04;
  CONNECTION_TYPE_WAN		       	 = $05;
  CONNECTION_TYPE_LAN			       = $06;
  CONNECTION_TYPE_AUTODETECT     = $07;

  {(* Client to Server (CS) data blocks *)}
  CS_CORE		      	= $C001;
  CS_SECURITY	     	= $C002;
  CS_NET			      = $C003;
  CS_CLUSTER	    	= $C004;
  CS_MONITOR	    	= $C005;
  CS_MCS_MSGCHANNEL	= $C006;
  CS_MONITOR_EX		  = $C008;
  CS_MULTITRANSPORT	= $C00A;

  {(* Server to Client (SC) data blocks *)}
  SC_CORE	      	 	= $0C01;
  SC_SECURITY   		= $0C02;
  SC_NET      			= $0C03;
  SC_MCS_MSGCHANNEL	= $0C04;
  SC_MULTITRANSPORT	= $0C08;

  {(* RDP versions, see
   * [MS-RDPBCGR] 2.2.1.3.2 Client Core Data (TS_UD_CS_CORE)
   * [MS-RDPBCGR] 2.2.1.4.2 Server Core Data (TS_UD_SC_CORE)
   *)}
type
  RDP_VERSION = (
    RDP_VERSION_4		= $00080001,
    RDP_VERSION_5_PLUS	= $00080004,
    RDP_VERSION_10_0	= $00080005,
    RDP_VERSION_10_1	= $00080006,
    RDP_VERSION_10_2	= $00080007,
    RDP_VERSION_10_3	= $00080008,
    RDP_VERSION_10_4	= $00080009,
    RDP_VERSION_10_5	= $0008000a,
    RDP_VERSION_10_6	= $0008000b
  );

const
  {(* Color depth *)}
  RNS_UD_COLOR_4BPP	     = $CA00;
  RNS_UD_COLOR_8BPP	     = $CA01;
  RNS_UD_COLOR_16BPP_555 = $CA02;
  RNS_UD_COLOR_16BPP_565 = $CA03;
  RNS_UD_COLOR_24BPP	   = $CA04;

  {(* Secure Access Sequence *)}
  RNS_UD_SAS_DEL	 =	$AA03;

  {(* Supported Color Depths *)}
  RNS_UD_24BPP_SUPPORT = $0001;
  RNS_UD_16BPP_SUPPORT = $0002;
  RNS_UD_15BPP_SUPPORT = $0004;
  RNS_UD_32BPP_SUPPORT = $0008;

  {(* Audio Mode *)}
  AUDIO_MODE_REDIRECT       = 0; {(* Bring to this computer *)}
  AUDIO_MODE_PLAY_ON_SERVER = 1; {(* Leave at remote computer *)}
  AUDIO_MODE_NONE           = 2; {(* Do not play *)}

  {(* Early Capability Flags (Client to Server) *)}
  RNS_UD_CS_SUPPORT_ERRINFO_PDU		     = $00001;
  RNS_UD_CS_WANT_32BPP_SESSION		     = $0002;
  RNS_UD_CS_SUPPORT_STATUSINFO_PDU	   = $0004;
  RNS_UD_CS_STRONG_ASYMMETRIC_KEYS	   = $0008;
  RNS_UD_CS_VALID_CONNECTION_TYPE		   = $0020;
  RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU = $0040;
  RNS_UD_CS_SUPPORT_NETWORK_AUTODETECT = $0080;
  RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL = $0100;
  RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE	 = $0200;
  RNS_UD_CS_SUPPORT_HEARTBEAT_PDU		   = $0400;

  {(* Early Capability Flags (Server to Client) *)}
  RNS_UD_SC_EDGE_ACTIONS_SUPPORTED	= $00000001;
  RNS_UD_SC_DYNAMIC_DST_SUPPORTED		= $00000002;

  {(* Cluster Information Flags *)}
  REDIRECTION_SUPPORTED			       = $00000001;
  REDIRECTED_SESSIONID_FIELD_VALID = $00000002;
  REDIRECTED_SMARTCARD			       = $00000040;

  REDIRECTION_VERSION1 = $00;
  REDIRECTION_VERSION2 = $01;
  REDIRECTION_VERSION3 = $02;
  REDIRECTION_VERSION4 = $03;
  REDIRECTION_VERSION5 = $04;
  REDIRECTION_VERSION6 = $05;

  MONITOR_PRIMARY = $00000001;

  {(* Encryption Methods *)}
  ENCRYPTION_METHOD_NONE      = $00000000;
  ENCRYPTION_METHOD_40BIT			= $00000001;
  ENCRYPTION_METHOD_128BIT		= $00000002;
  ENCRYPTION_METHOD_56BIT			= $00000008;
  ENCRYPTION_METHOD_FIPS			= $00000010;

  {(* Encryption Levels *)}
  ENCRYPTION_LEVEL_NONE			= $00000000;
  ENCRYPTION_LEVEL_LOW			= $00000001;
  ENCRYPTION_LEVEL_CLIENT_COMPATIBLE	= $00000002;
  ENCRYPTION_LEVEL_HIGH			= $00000003;
  ENCRYPTION_LEVEL_FIPS			= $00000004;

  {(* Multitransport Types *)}
  TRANSPORT_TYPE_UDP_FECR		   = $00000001;
  TRANSPORT_TYPE_UDP_FECL			 = $00000004;
  TRANSPORT_TYPE_UDP_PREFERRED = $00000100;

  {(* Static Virtual Channel Options *)}
  CHANNEL_OPTION_INITIALIZED        = $80000000;
  CHANNEL_OPTION_ENCRYPT_RDP        = $40000000;
  CHANNEL_OPTION_ENCRYPT_SC		      = $20000000;
  CHANNEL_OPTION_ENCRYPT_CS		      = $10000000;
  CHANNEL_OPTION_PRI_HIGH			      = $08000000;
  CHANNEL_OPTION_PRI_MED			      = $04000000;
  CHANNEL_OPTION_PRI_LOW            = $02000000;
  CHANNEL_OPTION_COMPRESS_RDP       = $00800000;
  CHANNEL_OPTION_COMPRESS           = $00400000;
  CHANNEL_OPTION_SHOW_PROTOCOL      = $00200000;
  CHANNEL_REMOTE_CONTROL_PERSISTENT = $00100000;

  {(* Auto Reconnect Version *)}
  AUTO_RECONNECT_VERSION_1		= $00000001;

  {(* Cookie Lengths *)}
  MSTSC_COOKIE_MAX_LENGTH			= 9;
  DEFAULT_COOKIE_MAX_LENGTH		= $FF;

  (* Order Support *)
  NEG_DSTBLT_INDEX = $00;
  NEG_PATBLT_INDEX = $01;
  NEG_SCRBLT_INDEX = $02;
  NEG_MEMBLT_INDEX = $03;
  NEG_MEM3BLT_INDEX = $04;
  NEG_ATEXTOUT_INDEX = $05;
  NEG_AEXTTEXTOUT_INDEX = $06; (* Must be ignored *)
  NEG_DRAWNINEGRID_INDEX = $07; (* Must be ignored *)
  NEG_LINETO_INDEX = $08;
  NEG_MULTI_DRAWNINEGRID_INDEX = $09;
  NEG_OPAQUE_RECT_INDEX = $0A; (* Must be ignored *)
  NEG_SAVEBITMAP_INDEX = $0B;
  NEG_WTEXTOUT_INDEX = $0C; (* Must be ignored *)
  NEG_MEMBLT_V2_INDEX = $0D; (* Must be ignored *)
  NEG_MEM3BLT_V2_INDEX = $0E; (* Must be ignored *)
  NEG_MULTIDSTBLT_INDEX = $0F;
  NEG_MULTIPATBLT_INDEX = $10;
  NEG_MULTISCRBLT_INDEX = $11;
  NEG_MULTIOPAQUERECT_INDEX = $12;
  NEG_FAST_INDEX_INDEX = $13;
  NEG_POLYGON_SC_INDEX = $14;
  NEG_POLYGON_CB_INDEX = $15;
  NEG_POLYLINE_INDEX = $16;
  NEG_UNUSED23_INDEX = $17; (* Must be ignored *)
  NEG_FAST_GLYPH_INDEX = $18;
  NEG_ELLIPSE_SC_INDEX = $19;
  NEG_ELLIPSE_CB_INDEX = $1A;
  NEG_GLYPH_INDEX_INDEX = $1B;
  NEG_GLYPH_WEXTTEXTOUT_INDEX = $1C; (* Must be ignored *)
  NEG_GLYPH_WLONGTEXTOUT_INDEX = $1D; (* Must be ignored *)
  NEG_GLYPH_WLONGEXTTEXTOUT_INDEX = $1E; (* Must be ignored *)
  NEG_UNUSED31_INDEX = $1F; (* Must be ignored *)

  (* Glyph Support Level *)
  GLYPH_SUPPORT_NONE = $0000;
  GLYPH_SUPPORT_PARTIAL = $0001;
  GLYPH_SUPPORT_FULL = $0002;
  GLYPH_SUPPORT_ENCODE = $0003;

  (* Gateway Usage Method *)
  TSC_PROXY_MODE_NONE_DIRECT = $0;
  TSC_PROXY_MODE_DIRECT = $1;
  TSC_PROXY_MODE_DETECT = $2;
  TSC_PROXY_MODE_DEFAULT = $3;
  TSC_PROXY_MODE_NONE_DETECT = $4;

  (* Gateway Credentials Source *)
  TSC_PROXY_CREDS_MODE_USERPASS = $0;
  TSC_PROXY_CREDS_MODE_SMARTCARD = $1;
  TSC_PROXY_CREDS_MODE_ANY = $2;

  (* Redirection Flags *)
  LB_TARGET_NET_ADDRESS = $00000001;
  LB_LOAD_BALANCE_INFO = $00000002;
  LB_USERNAME = $00000004;
  LB_DOMAIN = $00000008;
  LB_PASSWORD = $00000010;
  LB_DONTSTOREUSERNAME = $00000020;
  LB_SMARTCARD_LOGON = $00000040;
  LB_NOREDIRECT = $00000080;
  LB_TARGET_FQDN = $00000100;
  LB_TARGET_NETBIOS_NAME = $00000200;
  LB_TARGET_NET_ADDRESSES = $00000800;
  LB_CLIENT_TSV_URL = $00001000;
  LB_SERVER_TSV_CAPABLE = $00002000;

  LB_PASSWORD_MAX_LENGTH = 512;

  (* Keyboard Hook *)
  KEYBOARD_HOOK_LOCAL = 0;
  KEYBOARD_HOOK_REMOTE = 1;
  KEYBOARD_HOOK_FULLSCREEN_ONLY = 2;

type
  _TARGET_NET_ADDRESS = record
    Length: UINT32;
    Address: LPWSTR;
  end;
  TARGET_NET_ADDRESS = _TARGET_NET_ADDRESS;

const
  (* Logon Error Info *)
  LOGON_MSG_DISCONNECT_REFUSED = $FFFFFFF9;
  LOGON_MSG_NO_PERMISSION = $FFFFFFFA;
  LOGON_MSG_BUMP_OPTIONS = $FFFFFFFB;
  LOGON_MSG_RECONNECT_OPTIONS = $FFFFFFFC;
  LOGON_MSG_SESSION_TERMINATE = $FFFFFFFD;
  LOGON_MSG_SESSION_CONTINUE = $FFFFFFFE;

  LOGON_FAILED_BAD_PASSWORD = $00000000;
  LOGON_FAILED_UPDATE_PASSWORD = $00000001;
  LOGON_FAILED_OTHER = $00000002;
  LOGON_WARNING = $00000003;

  (* Server Status Info *)
  STATUS_FINDING_DESTINATION = $00000401;
  STATUS_LOADING_DESTINATION = $00000402;
  STATUS_BRINGING_SESSION_ONLINE = $00000403;
  STATUS_REDIRECTING_TO_DESTINATION = $00000404;
  STATUS_VM_LOADING = $00000501;
  STATUS_VM_WAKING = $00000502;
  STATUS_VM_BOOTING = $00000503;

  (* Compression Flags *)
  PACKET_COMPR_TYPE_8K = $00;
  PACKET_COMPR_TYPE_64K = $01;
  PACKET_COMPR_TYPE_RDP6 = $02;
  PACKET_COMPR_TYPE_RDP61 = $03;
  PACKET_COMPR_TYPE_RDP8 = $04;

  (* Desktop Rotation Flags *)
  ORIENTATION_LANDSCAPE = 0;
  ORIENTATION_PORTRAIT = 90;
  ORIENTATION_LANDSCAPE_FLIPPED = 180;
  ORIENTATION_PORTRAIT_FLIPPED = 270;

  (* Device Redirection *)

const
  RDPDR_DTYP_SERIAL = $00000001;
  RDPDR_DTYP_PARALLEL = $00000002;
  RDPDR_DTYP_PRINT = $00000004;
  RDPDR_DTYP_FILESYSTEM = $00000008;
  RDPDR_DTYP_SMARTCARD = $00000020;

type
  _RDPDR_DEVICE = record
    Id: UINT32;
    Type_: UINT32;
    Name: PAnsiChar;
  end;
  RDPDR_DEVICE = _RDPDR_DEVICE;
  TRdpRdDevice = RDPDR_DEVICE;
  PRdpRdDevice = ^TRdpRdDevice;
  PPRdpRdDevice = ^PRdpRdDevice;

  _RDPDR_DRIVE = record
    Id: UINT32;
    Type_: UINT32;
    Name: PAnsiChar;
    Path: PAnsiChar;
    automount: BOOL;
  end;
  RDPDR_DRIVE = _RDPDR_DRIVE;

  _RDPDR_PRINTER = record
    Id: UINT32;
    Type_: UINT32;
    Name: PAnsiChar;
    DriverName: PAnsiChar;
  end;
  RDPDR_PRINTER = _RDPDR_PRINTER;

  _RDPDR_SMARTCARD = record
    Id: UINT32;
    Type_: UINT32;
    Name: PAnsiChar;
  end;
  RDPDR_SMARTCARD = _RDPDR_SMARTCARD;

  _RDPDR_SERIAL = record
    Id: UINT32;
    Type_: UINT32;
    Name: PAnsiChar;
    Path: PAnsiChar;
    Driver: PAnsiChar;
    Permissive: PAnsiChar;
  end;
  RDPDR_SERIAL = _RDPDR_SERIAL;

  _RDPDR_PARALLEL = record
    Id: UINT32;
    Type_: UINT32;
    Name: PAnsiChar;
    Path: PAnsiChar;
  end;
  RDPDR_PARALLEL = _RDPDR_PARALLEL;

const
  PROXY_TYPE_NONE = 0;
  PROXY_TYPE_HTTP = 1;
  PROXY_TYPE_SOCKS = 2;
  PROXY_TYPE_IGNORE = $FFFF;

{* Settings *)}

(**
 * FreeRDP Settings Ids
 * This is generated with a script parsing the rdpSettings data structure
 *)

  FreeRDP_instance = (0);
  FreeRDP_ServerMode = (16);
  FreeRDP_ShareId = (17);
  FreeRDP_PduSource = (18);
  FreeRDP_ServerPort = (19);
  FreeRDP_ServerHostname = (20);
  FreeRDP_Username = (21);
  FreeRDP_Password = (22);
  FreeRDP_Domain = (23);
  FreeRDP_PasswordHash = (24);
  FreeRDP_WaitForOutputBufferFlush = (25);
  FreeRDP_MaxTimeInCheckLoop = (26);
  FreeRDP_AcceptedCert = (27);
  FreeRDP_AcceptedCertLength = (28);
  FreeRDP_RdpVersion = (128);
  FreeRDP_DesktopWidth = (129);
  FreeRDP_DesktopHeight = (130);
  FreeRDP_ColorDepth = (131);
  FreeRDP_ConnectionType = (132);
  FreeRDP_ClientBuild = (133);
  FreeRDP_ClientHostname = (134);
  FreeRDP_ClientProductId = (135);
  FreeRDP_EarlyCapabilityFlags = (136);
  FreeRDP_NetworkAutoDetect = (137);
  FreeRDP_SupportAsymetricKeys = (138);
  FreeRDP_SupportErrorInfoPdu = (139);
  FreeRDP_SupportStatusInfoPdu = (140);
  FreeRDP_SupportMonitorLayoutPdu = (141);
  FreeRDP_SupportGraphicsPipeline = (142);
  FreeRDP_SupportDynamicTimeZone = (143);
  FreeRDP_SupportHeartbeatPdu = (144);
  FreeRDP_DesktopPhysicalWidth = (145);
  FreeRDP_DesktopPhysicalHeight = (146);
  FreeRDP_DesktopOrientation = (147);
  FreeRDP_DesktopScaleFactor = (148);
  FreeRDP_DeviceScaleFactor = (149);
  FreeRDP_UseRdpSecurityLayer = (192);
  FreeRDP_EncryptionMethods = (193);
  FreeRDP_ExtEncryptionMethods = (194);
  FreeRDP_EncryptionLevel = (195);
  FreeRDP_ServerRandom = (196);
  FreeRDP_ServerRandomLength = (197);
  FreeRDP_ServerCertificate = (198);
  FreeRDP_ServerCertificateLength = (199);
  FreeRDP_ClientRandom = (200);
  FreeRDP_ClientRandomLength = (201);
  FreeRDP_ChannelCount = (256);
  FreeRDP_ChannelDefArraySize = (257);
  FreeRDP_ChannelDefArray = (258);
  FreeRDP_ClusterInfoFlags = (320);
  FreeRDP_RedirectedSessionId = (321);
  FreeRDP_ConsoleSession = (322);
  FreeRDP_MonitorCount = (384);
  FreeRDP_MonitorDefArraySize = (385);
  FreeRDP_MonitorDefArray = (386);
  FreeRDP_SpanMonitors = (387);
  FreeRDP_UseMultimon = (388);
  FreeRDP_ForceMultimon = (389);
  FreeRDP_DesktopPosX = (390);
  FreeRDP_DesktopPosY = (391);
  FreeRDP_ListMonitors = (392);
  FreeRDP_MonitorIds = (393);
  FreeRDP_NumMonitorIds = (394);
  FreeRDP_MonitorLocalShiftX = (395);
  FreeRDP_MonitorLocalShiftY = (396);
  FreeRDP_HasMonitorAttributes = (397);
  FreeRDP_MultitransportFlags = (512);
  FreeRDP_SupportMultitransport = (513);
  FreeRDP_AlternateShell = (640);
  FreeRDP_ShellWorkingDirectory = (641);
  FreeRDP_AutoLogonEnabled = (704);
  FreeRDP_CompressionEnabled = (705);
  FreeRDP_DisableCtrlAltDel = (706);
  FreeRDP_EnableWindowsKey = (707);
  FreeRDP_MaximizeShell = (708);
  FreeRDP_LogonNotify = (709);
  FreeRDP_LogonErrors = (710);
  FreeRDP_MouseAttached = (711);
  FreeRDP_MouseHasWheel = (712);
  FreeRDP_RemoteConsoleAudio = (713);
  FreeRDP_AudioPlayback = (714);
  FreeRDP_AudioCapture = (715);
  FreeRDP_VideoDisable = (716);
  FreeRDP_PasswordIsSmartcardPin = (717);
  FreeRDP_UsingSavedCredentials = (718);
  FreeRDP_ForceEncryptedCsPdu = (719);
  FreeRDP_HiDefRemoteApp = (720);
  FreeRDP_CompressionLevel = (721);
  FreeRDP_IPv6Enabled = (768);
  FreeRDP_ClientAddress = (769);
  FreeRDP_ClientDir = (770);
  FreeRDP_AutoReconnectionEnabled = (832);
  FreeRDP_AutoReconnectMaxRetries = (833);
  FreeRDP_ClientAutoReconnectCookie = (834);
  FreeRDP_ServerAutoReconnectCookie = (835);
  FreeRDP_PrintReconnectCookie = (836);
  FreeRDP_ClientTimeZone = (896);
  FreeRDP_DynamicDSTTimeZoneKeyName = (897);
  FreeRDP_DynamicDaylightTimeDisabled = (898);
  FreeRDP_PerformanceFlags = (960);
  FreeRDP_AllowFontSmoothing = (961);
  FreeRDP_DisableWallpaper = (962);
  FreeRDP_DisableFullWindowDrag = (963);
  FreeRDP_DisableMenuAnims = (964);
  FreeRDP_DisableThemes = (965);
  FreeRDP_DisableCursorShadow = (966);
  FreeRDP_DisableCursorBlinking = (967);
  FreeRDP_AllowDesktopComposition = (968);
  FreeRDP_RemoteAssistanceMode = (1024);
  FreeRDP_RemoteAssistanceSessionId = (1025);
  FreeRDP_RemoteAssistancePassStub = (1026);
  FreeRDP_RemoteAssistancePassword = (1027);
  FreeRDP_RemoteAssistanceRCTicket = (1028);
  FreeRDP_EncomspVirtualChannel = (1029);
  FreeRDP_RemdeskVirtualChannel = (1030);
  FreeRDP_LyncRdpMode = (1031);
  FreeRDP_TlsSecurity = (1088);
  FreeRDP_NlaSecurity = (1089);
  FreeRDP_RdpSecurity = (1090);
  FreeRDP_ExtSecurity = (1091);
  FreeRDP_Authentication = (1092);
  FreeRDP_RequestedProtocols = (1093);
  FreeRDP_SelectedProtocol = (1094);
  FreeRDP_NegotiationFlags = (1095);
  FreeRDP_NegotiateSecurityLayer = (1096);
  FreeRDP_RestrictedAdminModeRequired = (1097);
  FreeRDP_AuthenticationServiceClass = (1098);
  FreeRDP_DisableCredentialsDelegation = (1099);
  FreeRDP_AuthenticationLevel = (1100);
  FreeRDP_AllowedTlsCiphers = (1101);
  FreeRDP_VmConnectMode = (1102);
  FreeRDP_NtlmSamFile = (1103);
  FreeRDP_FIPSMode = (1104);
  FreeRDP_TlsSecLevel = (1105);
  FreeRDP_MstscCookieMode = (1152);
  FreeRDP_CookieMaxLength = (1153);
  FreeRDP_PreconnectionId = (1154);
  FreeRDP_PreconnectionBlob = (1155);
  FreeRDP_SendPreconnectionPdu = (1156);
  FreeRDP_RedirectionFlags = (1216);
  FreeRDP_TargetNetAddress = (1217);
  FreeRDP_LoadBalanceInfo = (1218);
  FreeRDP_LoadBalanceInfoLength = (1219);
  FreeRDP_RedirectionUsername = (1220);
  FreeRDP_RedirectionDomain = (1221);
  FreeRDP_RedirectionPassword = (1222);
  FreeRDP_RedirectionPasswordLength = (1223);
  FreeRDP_RedirectionTargetFQDN = (1224);
  FreeRDP_RedirectionTargetNetBiosName = (1225);
  FreeRDP_RedirectionTsvUrl = (1226);
  FreeRDP_RedirectionTsvUrlLength = (1227);
  FreeRDP_TargetNetAddressCount = (1228);
  FreeRDP_TargetNetAddresses = (1229);
  FreeRDP_TargetNetPorts = (1230);
  FreeRDP_RedirectionAcceptedCert = (1231);
  FreeRDP_RedirectionAcceptedCertLength = (1232);
  FreeRDP_RedirectionPreferType = (1233);
  FreeRDP_Password51 = (1280);
  FreeRDP_Password51Length = (1281);
  FreeRDP_SmartcardLogon = (1282);
  FreeRDP_PromptForCredentials = (1283);
  FreeRDP_KerberosKdc = (1344);
  FreeRDP_KerberosRealm = (1345);
  FreeRDP_IgnoreCertificate = (1408);
  FreeRDP_CertificateName = (1409);
  FreeRDP_CertificateFile = (1410);
  FreeRDP_PrivateKeyFile = (1411);
  FreeRDP_RdpKeyFile = (1412);
  FreeRDP_RdpServerRsaKey = (1413);
  FreeRDP_RdpServerCertificate = (1414);
  FreeRDP_ExternalCertificateManagement = (1415);
  FreeRDP_CertificateContent = (1416);
  FreeRDP_PrivateKeyContent = (1417);
  FreeRDP_RdpKeyContent = (1418);
  FreeRDP_AutoAcceptCertificate = (1419);
  FreeRDP_AutoDenyCertificate = (1420);
  FreeRDP_Workarea = (1536);
  FreeRDP_Fullscreen = (1537);
  FreeRDP_PercentScreen = (1538);
  FreeRDP_GrabKeyboard = (1539);
  FreeRDP_Decorations = (1540);
  FreeRDP_MouseMotion = (1541);
  FreeRDP_WindowTitle = (1542);
  FreeRDP_ParentWindowId = (1543);
  FreeRDP_AsyncInput = (1544);
  FreeRDP_AsyncUpdate = (1545);
  FreeRDP_AsyncChannels = (1546);
  FreeRDP_ToggleFullscreen = (1548);
  FreeRDP_WmClass = (1549);
  FreeRDP_EmbeddedWindow = (1550);
  FreeRDP_SmartSizing = (1551);
  FreeRDP_XPan = (1552);
  FreeRDP_YPan = (1553);
  FreeRDP_SmartSizingWidth = (1554);
  FreeRDP_SmartSizingHeight = (1555);
  FreeRDP_PercentScreenUseWidth = (1556);
  FreeRDP_PercentScreenUseHeight = (1557);
  FreeRDP_DynamicResolutionUpdate = (1558);
  FreeRDP_SoftwareGdi = (1601);
  FreeRDP_LocalConnection = (1602);
  FreeRDP_AuthenticationOnly = (1603);
  FreeRDP_CredentialsFromStdin = (1604);
  FreeRDP_UnmapButtons = (1605);
  FreeRDP_OldLicenseBehaviour = (1606);
  FreeRDP_ComputerName = (1664);
  FreeRDP_ConnectionFile = (1728);
  FreeRDP_AssistanceFile = (1729);
  FreeRDP_HomePath = (1792);
  FreeRDP_ConfigPath = (1793);
  FreeRDP_CurrentPath = (1794);
  FreeRDP_DumpRemoteFx = (1856);
  FreeRDP_PlayRemoteFx = (1857);
  FreeRDP_DumpRemoteFxFile = (1858);
  FreeRDP_PlayRemoteFxFile = (1859);
  FreeRDP_GatewayUsageMethod = (1984);
  FreeRDP_GatewayPort = (1985);
  FreeRDP_GatewayHostname = (1986);
  FreeRDP_GatewayUsername = (1987);
  FreeRDP_GatewayPassword = (1988);
  FreeRDP_GatewayDomain = (1989);
  FreeRDP_GatewayCredentialsSource = (1990);
  FreeRDP_GatewayUseSameCredentials = (1991);
  FreeRDP_GatewayEnabled = (1992);
  FreeRDP_GatewayBypassLocal = (1993);
  FreeRDP_GatewayRpcTransport = (1994);
  FreeRDP_GatewayHttpTransport = (1995);
  FreeRDP_GatewayUdpTransport = (1996);
  FreeRDP_GatewayAccessToken = (1997);
  FreeRDP_GatewayAcceptedCert = (1998);
  FreeRDP_GatewayAcceptedCertLength = (1999);
  FreeRDP_ProxyType = (2015);
  FreeRDP_ProxyHostname = (2016);
  FreeRDP_ProxyPort = (2017);
  FreeRDP_ProxyUsername = (2018);
  FreeRDP_ProxyPassword = (2019);
  FreeRDP_RemoteApplicationMode = (2112);
  FreeRDP_RemoteApplicationName = (2113);
  FreeRDP_RemoteApplicationIcon = (2114);
  FreeRDP_RemoteApplicationProgram = (2115);
  FreeRDP_RemoteApplicationFile = (2116);
  FreeRDP_RemoteApplicationGuid = (2117);
  FreeRDP_RemoteApplicationCmdLine = (2118);
  FreeRDP_RemoteApplicationExpandCmdLine = (2119);
  FreeRDP_RemoteApplicationExpandWorkingDir = (2120);
  FreeRDP_DisableRemoteAppCapsCheck = (2121);
  FreeRDP_RemoteAppNumIconCaches = (2122);
  FreeRDP_RemoteAppNumIconCacheEntries = (2123);
  FreeRDP_RemoteAppLanguageBarSupported = (2124);
  FreeRDP_RemoteWndSupportLevel = (2125);
  FreeRDP_RemoteApplicationSupportLevel = (2126);
  FreeRDP_RemoteApplicationSupportMask = (2127);
  FreeRDP_RemoteApplicationWorkingDir = (2128);
  FreeRDP_ReceivedCapabilities = (2240);
  FreeRDP_ReceivedCapabilitiesSize = (2241);
  FreeRDP_OsMajorType = (2304);
  FreeRDP_OsMinorType = (2305);
  FreeRDP_RefreshRect = (2306);
  FreeRDP_SuppressOutput = (2307);
  FreeRDP_FastPathOutput = (2308);
  FreeRDP_SaltedChecksum = (2309);
  FreeRDP_LongCredentialsSupported = (2310);
  FreeRDP_NoBitmapCompressionHeader = (2311);
  FreeRDP_BitmapCompressionDisabled = (2312);
  FreeRDP_DesktopResize = (2368);
  FreeRDP_DrawAllowDynamicColorFidelity = (2369);
  FreeRDP_DrawAllowColorSubsampling = (2370);
  FreeRDP_DrawAllowSkipAlpha = (2371);
  FreeRDP_OrderSupport = (2432);
  FreeRDP_BitmapCacheV3Enabled = (2433);
  FreeRDP_AltSecFrameMarkerSupport = (2434);
  FreeRDP_AllowUnanouncedOrdersFromServer = (2435);
  FreeRDP_BitmapCacheEnabled = (2497);
  FreeRDP_BitmapCacheVersion = (2498);
  FreeRDP_AllowCacheWaitingList = (2499);
  FreeRDP_BitmapCachePersistEnabled = (2500);
  FreeRDP_BitmapCacheV2NumCells = (2501);
  FreeRDP_BitmapCacheV2CellInfo = (2502);
  FreeRDP_ColorPointerFlag = (2560);
  FreeRDP_PointerCacheSize = (2561);
  FreeRDP_KeyboardLayout = (2624);
  FreeRDP_KeyboardType = (2625);
  FreeRDP_KeyboardSubType = (2626);
  FreeRDP_KeyboardFunctionKey = (2627);
  FreeRDP_ImeFileName = (2628);
  FreeRDP_UnicodeInput = (2629);
  FreeRDP_FastPathInput = (2630);
  FreeRDP_MultiTouchInput = (2631);
  FreeRDP_MultiTouchGestures = (2632);
  FreeRDP_KeyboardHook = (2633);
  FreeRDP_HasHorizontalWheel = (2634);
  FreeRDP_HasExtendedMouseEvent = (2635);
  FreeRDP_BrushSupportLevel = (2688);
  FreeRDP_GlyphSupportLevel = (2752);
  FreeRDP_GlyphCache = (2753);
  FreeRDP_FragCache = (2754);
  FreeRDP_OffscreenSupportLevel = (2816);
  FreeRDP_OffscreenCacheSize = (2817);
  FreeRDP_OffscreenCacheEntries = (2818);
  FreeRDP_VirtualChannelCompressionFlags = (2880);
  FreeRDP_VirtualChannelChunkSize = (2881);
  FreeRDP_SoundBeepsEnabled = (2944);
  FreeRDP_MultifragMaxRequestSize = (3328);
  FreeRDP_LargePointerFlag = (3392);
  FreeRDP_CompDeskSupportLevel = (3456);
  FreeRDP_SurfaceCommandsEnabled = (3520);
  FreeRDP_FrameMarkerCommandEnabled = (3521);
  FreeRDP_SurfaceFrameMarkerEnabled = (3522);
  FreeRDP_RemoteFxOnly = (3648);
  FreeRDP_RemoteFxCodec = (3649);
  FreeRDP_RemoteFxCodecId = (3650);
  FreeRDP_RemoteFxCodecMode = (3651);
  FreeRDP_RemoteFxImageCodec = (3652);
  FreeRDP_RemoteFxCaptureFlags = (3653);
  FreeRDP_NSCodec = (3712);
  FreeRDP_NSCodecId = (3713);
  FreeRDP_FrameAcknowledge = (3714);
  FreeRDP_NSCodecColorLossLevel = (3715);
  FreeRDP_NSCodecAllowSubsampling = (3716);
  FreeRDP_NSCodecAllowDynamicColorFidelity = (3717);
  FreeRDP_JpegCodec = (3776);
  FreeRDP_JpegCodecId = (3777);
  FreeRDP_JpegQuality = (3778);
  FreeRDP_GfxThinClient = (3840);
  FreeRDP_GfxSmallCache = (3841);
  FreeRDP_GfxProgressive = (3842);
  FreeRDP_GfxProgressiveV2 = (3843);
  FreeRDP_GfxH264 = (3844);
  FreeRDP_GfxAVC444 = (3845);
  FreeRDP_GfxSendQoeAck = (3846);
  FreeRDP_GfxAVC444v2 = (3847);
  FreeRDP_GfxCapsFilter = (3848);
  FreeRDP_BitmapCacheV3CodecId = (3904);
  FreeRDP_DrawNineGridEnabled = (3968);
  FreeRDP_DrawNineGridCacheSize = (3969);
  FreeRDP_DrawNineGridCacheEntries = (3970);
  FreeRDP_DrawGdiPlusEnabled = (4032);
  FreeRDP_DrawGdiPlusCacheEnabled = (4033);
  FreeRDP_DeviceRedirection = (4160);
  FreeRDP_DeviceCount = (4161);
  FreeRDP_DeviceArraySize = (4162);
  FreeRDP_DeviceArray = (4163);
  FreeRDP_RedirectDrives = (4288);
  FreeRDP_RedirectHomeDrive = (4289);
  FreeRDP_DrivesToRedirect = (4290);
  FreeRDP_RedirectSmartCards = (4416);
  FreeRDP_RedirectPrinters = (4544);
  FreeRDP_RedirectSerialPorts = (4672);
  FreeRDP_RedirectParallelPorts = (4673);
  FreeRDP_PreferIPv6OverIPv4 = (4674);
  FreeRDP_RedirectClipboard = (4800);
  FreeRDP_StaticChannelCount = (4928);
  FreeRDP_StaticChannelArraySize = (4929);
  FreeRDP_StaticChannelArray = (4930);
  FreeRDP_DynamicChannelCount = (5056);
  FreeRDP_DynamicChannelArraySize = (5057);
  FreeRDP_DynamicChannelArray = (5058);
  FreeRDP_SupportDynamicChannels = (5059);
  FreeRDP_SupportEchoChannel = (5184);
  FreeRDP_SupportDisplayControl = (5185);
  FreeRDP_SupportGeometryTracking = (5186);
  FreeRDP_SupportSSHAgentChannel = (5187);
  FreeRDP_SupportVideoOptimized = (5188);
  FreeRDP_RDP2TCPArgs = (5189);


(**
 * FreeRDP Settings Data Structure
 *)

const
(**
  * rdpSettings creation flags
  *)
  FREERDP_SETTINGS_SERVER_MODE = $00000001;
{$ENDREGION} // settings.h

{$REGION 'wtsapi.h'}
const
  CHANNEL_RC_OK				              	= 0;
  CHANNEL_RC_ALREADY_INITIALIZED			= 1;
  CHANNEL_RC_NOT_INITIALIZED	    		= 2;
  CHANNEL_RC_ALREADY_CONNECTED	  		= 3;
  CHANNEL_RC_NOT_CONNECTED		      	= 4;
  CHANNEL_RC_TOO_MANY_CHANNELS	  		= 5;
  CHANNEL_RC_BAD_CHANNEL			      	= 6;
  CHANNEL_RC_BAD_CHANNEL_HANDLE		  	= 7;
  CHANNEL_RC_NO_BUFFER			        	= 8;
  CHANNEL_RC_BAD_INIT_HANDLE	    		= 9;
  CHANNEL_RC_NOT_OPEN		          		= 10;
  CHANNEL_RC_BAD_PROC		          		= 11;
  CHANNEL_RC_NO_MEMORY		        		= 12;
  CHANNEL_RC_UNKNOWN_CHANNEL_NAME			= 13;
  CHANNEL_RC_ALREADY_OPEN		      		= 14;
  CHANNEL_RC_NOT_IN_VIRTUALCHANNELENTRY		= 15;
  CHANNEL_RC_NULL_DATA			        	= 16;
  CHANNEL_RC_ZERO_LENGTH		      		= 17;
  CHANNEL_RC_INVALID_INSTANCE		    	= 18;
  CHANNEL_RC_UNSUPPORTED_VERSION			= 19;
  CHANNEL_RC_INITIALIZATION_ERROR			= 20;
{$ENDREGION}

{$REGION 'errors.h'}
(* Protocol-independent codes *)
const
  ERRINFO_RPC_INITIATED_DISCONNECT = $00000001;
  ERRINFO_RPC_INITIATED_LOGOFF = $00000002;
  ERRINFO_IDLE_TIMEOUT = $00000003;
  ERRINFO_LOGON_TIMEOUT = $00000004;
  ERRINFO_DISCONNECTED_BY_OTHER_CONNECTION = $00000005;
  ERRINFO_OUT_OF_MEMORY = $00000006;
  ERRINFO_SERVER_DENIED_CONNECTION = $00000007;
  ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES = $00000009;
  ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED = $0000000A;
  ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER = $0000000B;
  ERRINFO_LOGOFF_BY_USER = $0000000C;

  (* Protocol-independent licensing codes *)
  ERRINFO_LICENSE_INTERNAL = $00000100;
  ERRINFO_LICENSE_NO_LICENSE_SERVER = $00000101;
  ERRINFO_LICENSE_NO_LICENSE = $00000102;
  ERRINFO_LICENSE_BAD_CLIENT_MSG = $00000103;
  ERRINFO_LICENSE_HWID_DOESNT_MATCH_LICENSE = $00000104;
  ERRINFO_LICENSE_BAD_CLIENT_LICENSE = $00000105;
  ERRINFO_LICENSE_CANT_FINISH_PROTOCOL = $00000106;
  ERRINFO_LICENSE_CLIENT_ENDED_PROTOCOL = $00000107;
  ERRINFO_LICENSE_BAD_CLIENT_ENCRYPTION = $00000108;
  ERRINFO_LICENSE_CANT_UPGRADE_LICENSE = $00000109;
  ERRINFO_LICENSE_NO_REMOTE_CONNECTIONS = $0000010A;

  (* Protocol-independent codes generated by the Connection Broker *)
  ERRINFO_CB_DESTINATION_NOT_FOUND = $0000400;
  ERRINFO_CB_LOADING_DESTINATION = $0000402;
  ERRINFO_CB_REDIRECTING_TO_DESTINATION = $0000404;
  ERRINFO_CB_SESSION_ONLINE_VM_WAKE = $0000405;
  ERRINFO_CB_SESSION_ONLINE_VM_BOOT = $0000406;
  ERRINFO_CB_SESSION_ONLINE_VM_NO_DNS = $0000407;
  ERRINFO_CB_DESTINATION_POOL_NOT_FREE = $0000408;
  ERRINFO_CB_CONNECTION_CANCELLED = $0000409;
  ERRINFO_CB_CONNECTION_ERROR_INVALID_SETTINGS = $0000410;
  ERRINFO_CB_SESSION_ONLINE_VM_BOOT_TIMEOUT = $0000411;
  ERRINFO_CB_SESSION_ONLINE_VM_SESSMON_FAILED = $0000412;

  (* RDP specific codes *)
  ERRINFO_UNKNOWN_DATA_PDU_TYPE = $000010C9;
  ERRINFO_UNKNOWN_PDU_TYPE = $000010CA;
  ERRINFO_DATA_PDU_SEQUENCE = $000010CB;
  ERRINFO_CONTROL_PDU_SEQUENCE = $000010CD;
  ERRINFO_INVALID_CONTROL_PDU_ACTION = $000010CE;
  ERRINFO_INVALID_INPUT_PDU_TYPE = $000010CF;
  ERRINFO_INVALID_INPUT_PDU_MOUSE = $000010D0;
  ERRINFO_INVALID_REFRESH_RECT_PDU = $000010D1;
  ERRINFO_CREATE_USER_DATA_FAILED = $000010D2;
  ERRINFO_CONNECT_FAILED = $000010D3;
  ERRINFO_CONFIRM_ACTIVE_HAS_WRONG_SHAREID = $000010D4;
  ERRINFO_CONFIRM_ACTIVE_HAS_WRONG_ORIGINATOR = $000010D5;
  ERRINFO_PERSISTENT_KEY_PDU_BAD_LENGTH = $000010DA;
  ERRINFO_PERSISTENT_KEY_PDU_ILLEGAL_FIRST = $000010DB;
  ERRINFO_PERSISTENT_KEY_PDU_TOO_MANY_TOTAL_KEYS = $000010DC;
  ERRINFO_PERSISTENT_KEY_PDU_TOO_MANY_CACHE_KEYS = $000010DD;
  ERRINFO_INPUT_PDU_BAD_LENGTH = $000010DE;
  ERRINFO_BITMAP_CACHE_ERROR_PDU_BAD_LENGTH = $000010DF;
  ERRINFO_SECURITY_DATA_TOO_SHORT = $000010E0;
  ERRINFO_VCHANNEL_DATA_TOO_SHORT = $000010E1;
  ERRINFO_SHARE_DATA_TOO_SHORT = $000010E2;
  ERRINFO_BAD_SUPPRESS_OUTPUT_PDU = $000010E3;
  ERRINFO_CONFIRM_ACTIVE_PDU_TOO_SHORT = $000010E5;
  ERRINFO_CAPABILITY_SET_TOO_SMALL = $000010E7;
  ERRINFO_CAPABILITY_SET_TOO_LARGE = $000010E8;
  ERRINFO_NO_CURSOR_CACHE = $000010E9;
  ERRINFO_BAD_CAPABILITIES = $000010EA;
  ERRINFO_VIRTUAL_CHANNEL_DECOMPRESSION = $000010EC;
  ERRINFO_INVALID_VC_COMPRESSION_TYPE = $000010ED;
  ERRINFO_INVALID_CHANNEL_ID = $000010EF;
  ERRINFO_VCHANNELS_TOO_MANY = $000010F0;
  ERRINFO_REMOTEAPP_NOT_ENABLED = $000010F3;
  ERRINFO_CACHE_CAP_NOT_SET = $000010F4;
  ERRINFO_BITMAP_CACHE_ERROR_PDU_BAD_LENGTH2 = $000010F5;
  ERRINFO_OFFSCREEN_CACHE_ERROR_PDU_BAD_LENGTH = $000010F6;
  ERRINFO_DRAWNINEGRID_CACHE_ERROR_PDU_BAD_LENGTH = $000010F7;
  ERRINFO_GDIPLUS_PDU_BAD_LENGTH = $000010F8;
  ERRINFO_SECURITY_DATA_TOO_SHORT2 = $00001111;
  ERRINFO_SECURITY_DATA_TOO_SHORT3 = $00001112;
  ERRINFO_SECURITY_DATA_TOO_SHORT4 = $00001113;
  ERRINFO_SECURITY_DATA_TOO_SHORT5 = $00001114;
  ERRINFO_SECURITY_DATA_TOO_SHORT6 = $00001115;
  ERRINFO_SECURITY_DATA_TOO_SHORT7 = $00001116;
  ERRINFO_SECURITY_DATA_TOO_SHORT8 = $00001117;
  ERRINFO_SECURITY_DATA_TOO_SHORT9 = $00001118;
  ERRINFO_SECURITY_DATA_TOO_SHORT10 = $00001119;
  ERRINFO_SECURITY_DATA_TOO_SHORT11 = $0000111A;
  ERRINFO_SECURITY_DATA_TOO_SHORT12 = $0000111B;
  ERRINFO_SECURITY_DATA_TOO_SHORT13 = $0000111C;
  ERRINFO_SECURITY_DATA_TOO_SHORT14 = $0000111D;
  ERRINFO_SECURITY_DATA_TOO_SHORT15 = $0000111E;
  ERRINFO_SECURITY_DATA_TOO_SHORT16 = $0000111F;
  ERRINFO_SECURITY_DATA_TOO_SHORT17 = $00001120;
  ERRINFO_SECURITY_DATA_TOO_SHORT18 = $00001121;
  ERRINFO_SECURITY_DATA_TOO_SHORT19 = $00001122;
  ERRINFO_SECURITY_DATA_TOO_SHORT20 = $00001123;
  ERRINFO_SECURITY_DATA_TOO_SHORT21 = $00001124;
  ERRINFO_SECURITY_DATA_TOO_SHORT22 = $00001125;
  ERRINFO_SECURITY_DATA_TOO_SHORT23 = $00001126;
  ERRINFO_BAD_MONITOR_DATA = $00001129;
  ERRINFO_VC_DECOMPRESSED_REASSEMBLE_FAILED = $0000112A;
  ERRINFO_VC_DATA_TOO_LONG = $0000112B;
  ERRINFO_BAD_FRAME_ACK_DATA = $0000112C;
  ERRINFO_GRAPHICS_MODE_NOT_SUPPORTED = $0000112D;
  ERRINFO_GRAPHICS_SUBSYSTEM_RESET_FAILED = $0000112E;
  ERRINFO_GRAPHICS_SUBSYSTEM_FAILED = $0000112F;
  ERRINFO_TIMEZONE_KEY_NAME_LENGTH_TOO_SHORT = $00001130;
  ERRINFO_TIMEZONE_KEY_NAME_LENGTH_TOO_LONG = $00001131;
  ERRINFO_DYNAMIC_DST_DISABLED_FIELD_MISSING = $00001132;
  ERRINFO_VC_DECODING_ERROR = $00001133;
  ERRINFO_VIRTUALDESKTOPTOOLARGE = $00001134;
  ERRINFO_MONITORGEOMETRYVALIDATIONFAILED = $00001135;
  ERRINFO_INVALIDMONITORCOUNT = $00001136;
  ERRINFO_UPDATE_SESSION_KEY_FAILED = $00001191;
  ERRINFO_DECRYPT_FAILED = $00001192;
  ERRINFO_ENCRYPT_FAILED = $00001193;
  ERRINFO_ENCRYPTION_PACKAGE_MISMATCH = $00001194;
  ERRINFO_DECRYPT_FAILED2 = $00001195;
  ERRINFO_PEER_DISCONNECTED = $00001196;

  ERRINFO_SUCCESS = $00000000;
  ERRINFO_NONE = $FFFFFFFF;

  FREERDP_ERROR_BASE = 0;

  (**
   * Error Base Codes
   *)
  FREERDP_ERROR_ERRBASE_CLASS = (FREERDP_ERROR_BASE+0);

  ERRBASE_SUCCESS = ERRINFO_SUCCESS;
  ERRBASE_NONE = ERRINFO_NONE;

  (* Error Info Codes *)

  FREERDP_ERROR_ERRINFO_CLASS = (FREERDP_ERROR_BASE+1);
{
  FREERDP_ERROR_RPC_INITIATED_DISCONNECT = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_RPC_INITIATED_DISCONNECT);
  FREERDP_ERROR_RPC_INITIATED_LOGOFF = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_RPC_INITIATED_LOGOFF);
  FREERDP_ERROR_IDLE_TIMEOUT = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_IDLE_TIMEOUT);
  FREERDP_ERROR_LOGON_TIMEOUT = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_LOGON_TIMEOUT);
  FREERDP_ERROR_DISCONNECTED_BY_OTHER_CONNECTION = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_DISCONNECTED_BY_OTHER_CONNECTION);
  FREERDP_ERROR_OUT_OF_MEMORY = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_OUT_OF_MEMORY);
  FREERDP_ERROR_SERVER_DENIED_CONNECTION = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_SERVER_DENIED_CONNECTION);
  FREERDP_ERROR_SERVER_INSUFFICIENT_PRIVILEGES = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES);
  FREERDP_ERROR_SERVER_FRESH_CREDENTIALS_REQUIRED = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED);
  FREERDP_ERROR_RPC_INITIATED_DISCONNECT_BY_USER = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER);
  FREERDP_ERROR_LOGOFF_BY_USER = MAKE_FREERDP_ERROR(ERRINFO,ERRINFO_LOGOFF_BY_USER);
}
  (* Connection Error Codes *)
  ERRCONNECT_PRE_CONNECT_FAILED = $00000001;
  ERRCONNECT_CONNECT_UNDEFINED = $00000002;
  ERRCONNECT_POST_CONNECT_FAILED = $00000003;
  ERRCONNECT_DNS_ERROR = $00000004;
  ERRCONNECT_DNS_NAME_NOT_FOUND = $00000005;
  ERRCONNECT_CONNECT_FAILED = $00000006;
  ERRCONNECT_MCS_CONNECT_INITIAL_ERROR = $00000007;
  ERRCONNECT_TLS_CONNECT_FAILED = $00000008;
  ERRCONNECT_AUTHENTICATION_FAILED = $00000009;
  ERRCONNECT_INSUFFICIENT_PRIVILEGES = $0000000A;
  ERRCONNECT_CONNECT_CANCELLED = $0000000B;
  ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED = $0000000C;
  ERRCONNECT_CONNECT_TRANSPORT_FAILED = $0000000D;
  ERRCONNECT_PASSWORD_EXPIRED = $0000000E;
  (* For non-domain workstation where we can't contact a kerberos server *)
  ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED = $0000000F;
  ERRCONNECT_CLIENT_REVOKED = $00000010;
  ERRCONNECT_KDC_UNREACHABLE = $00000011;

  ERRCONNECT_ACCOUNT_DISABLED = $00000012;
  ERRCONNECT_PASSWORD_MUST_CHANGE = $00000013;
  ERRCONNECT_LOGON_FAILURE = $00000014;
  ERRCONNECT_WRONG_PASSWORD = $00000015;
  ERRCONNECT_ACCESS_DENIED = $00000016;
  ERRCONNECT_ACCOUNT_RESTRICTION = $00000017;
  ERRCONNECT_ACCOUNT_LOCKED_OUT = $00000018;
  ERRCONNECT_ACCOUNT_EXPIRED = $00000019;
  ERRCONNECT_LOGON_TYPE_NOT_GRANTED = $0000001A;
  ERRCONNECT_NO_OR_MISSING_CREDENTIALS = $0000001B;


  ERRCONNECT_SUCCESS = ERRINFO_SUCCESS;
  ERRCONNECT_NONE = ERRINFO_NONE;

//FREERDP_API const char* freerdp_get_error_connect_string(UINT32 code);
//FREERDP_API const char* freerdp_get_error_connect_name(UINT32 code);

  FREERDP_ERROR_CONNECT_CLASS	= FREERDP_ERROR_BASE + 2;

  FREERDP_ERROR_PRE_CONNECT_FAILED                = (FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_PRE_CONNECT_FAILED;
  FREERDP_ERROR_CONNECT_UNDEFINED                 =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_CONNECT_UNDEFINED;
  FREERDP_ERROR_POST_CONNECT_FAILED               = (FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_POST_CONNECT_FAILED;
  FREERDP_ERROR_DNS_ERROR                         = (FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_DNS_ERROR;
  FREERDP_ERROR_DNS_NAME_NOT_FOUND                =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_DNS_NAME_NOT_FOUND;
  FREERDP_ERROR_CONNECT_FAILED                    =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_CONNECT_FAILED;
  FREERDP_ERROR_MCS_CONNECT_INITIAL_ERROR         =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_MCS_CONNECT_INITIAL_ERROR;
  FREERDP_ERROR_TLS_CONNECT_FAILED                = (FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_TLS_CONNECT_FAILED;
  FREERDP_ERROR_AUTHENTICATION_FAILED             =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_AUTHENTICATION_FAILED;
  FREERDP_ERROR_INSUFFICIENT_PRIVILEGES           =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_INSUFFICIENT_PRIVILEGES;
  FREERDP_ERROR_CONNECT_CANCELLED                 =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_CONNECT_CANCELLED;
  FREERDP_ERROR_SECURITY_NEGO_CONNECT_FAILED      =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED;
  FREERDP_ERROR_CONNECT_TRANSPORT_FAILED          =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_CONNECT_TRANSPORT_FAILED;
  FREERDP_ERROR_CONNECT_PASSWORD_EXPIRED          =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_PASSWORD_EXPIRED;
  FREERDP_ERROR_CONNECT_PASSWORD_MUST_CHANGE      =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_PASSWORD_MUST_CHANGE;
  FREERDP_ERROR_CONNECT_KDC_UNREACHABLE           =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_KDC_UNREACHABLE;
  FREERDP_ERROR_CONNECT_ACCOUNT_DISABLED          =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_ACCOUNT_DISABLED;
  FREERDP_ERROR_CONNECT_PASSWORD_CERTAINLY_EXPIRED=	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED;
  FREERDP_ERROR_CONNECT_CLIENT_REVOKED            =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_CLIENT_REVOKED;
  FREERDP_ERROR_CONNECT_LOGON_FAILURE             =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_LOGON_FAILURE;
  FREERDP_ERROR_CONNECT_WRONG_PASSWORD            =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_WRONG_PASSWORD;
  FREERDP_ERROR_CONNECT_ACCESS_DENIED             =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_ACCESS_DENIED;
  FREERDP_ERROR_CONNECT_ACCOUNT_RESTRICTION       =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_ACCOUNT_RESTRICTION;
  FREERDP_ERROR_CONNECT_ACCOUNT_LOCKED_OUT        =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_ACCOUNT_LOCKED_OUT;
  FREERDP_ERROR_CONNECT_ACCOUNT_EXPIRED           =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_ACCOUNT_EXPIRED;
  FREERDP_ERROR_CONNECT_LOGON_TYPE_NOT_GRANTED    = (FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_LOGON_TYPE_NOT_GRANTED;
  FREERDP_ERROR_CONNECT_NO_OR_MISSING_CREDENTIALS =	(FREERDP_ERROR_CONNECT_CLASS shl 16) or ERRCONNECT_NO_OR_MISSING_CREDENTIALS;

{$ENDREGION}

function freerdp_context_new(instance: PFreeRdp): BOOL; cdecl;
procedure freerdp_context_free(instance: PFreeRdp); cdecl;

function freerdp_connect(instance: PFreeRdp): BOOL; cdecl;
function freerdp_abort_connect(instance: PFreeRdp): BOOL; cdecl;
function freerdp_shall_disconnect(instance: PFreeRdp): BOOL; cdecl;
function freerdp_disconnect(instance: PFreeRdp): BOOL; cdecl;

{
FREERDP_API BOOL freerdp_disconnect_before_reconnect(freerdp* instance);
FREERDP_API BOOL freerdp_reconnect(freerdp* instance);

FREERDP_API UINT freerdp_channel_add_init_handle_data(rdpChannelHandles* handles, void* pInitHandle,
        void* pUserData);
FREERDP_API void* freerdp_channel_get_init_handle_data(rdpChannelHandles* handles,
        void* pInitHandle);
FREERDP_API void freerdp_channel_remove_init_handle_data(rdpChannelHandles* handles,
        void* pInitHandle);

FREERDP_API UINT freerdp_channel_add_open_handle_data(rdpChannelHandles* handles, DWORD openHandle,
        void* pUserData);
FREERDP_API void* freerdp_channel_get_open_handle_data(rdpChannelHandles* handles,
        DWORD openHandle);
FREERDP_API void freerdp_channel_remove_open_handle_data(rdpChannelHandles* handles,
        DWORD openHandle);

FREERDP_API UINT freerdp_channels_attach(freerdp* instance);
FREERDP_API UINT freerdp_channels_detach(freerdp* instance);

FREERDP_API BOOL freerdp_get_fds(freerdp* instance, void** rfds, int* rcount,
                                 void** wfds, int* wcount);
FREERDP_API BOOL freerdp_check_fds(freerdp* instance);

FREERDP_API DWORD freerdp_get_event_handles(rdpContext* context, HANDLE* events,
        DWORD count);
FREERDP_API BOOL freerdp_check_event_handles(rdpContext* context);

FREERDP_API wMessageQueue* freerdp_get_message_queue(freerdp* instance,
        DWORD id);
FREERDP_API HANDLE freerdp_get_message_queue_event_handle(freerdp* instance,
        DWORD id);
FREERDP_API int freerdp_message_queue_process_message(freerdp* instance,
        DWORD id, wMessage* message);
FREERDP_API int freerdp_message_queue_process_pending_messages(
    freerdp* instance, DWORD id);

FREERDP_API UINT32 freerdp_error_info(freerdp* instance);
FREERDP_API void freerdp_set_error_info(rdpRdp* rdp, UINT32 error);
FREERDP_API BOOL freerdp_send_error_info(rdpRdp* rdp);

FREERDP_API void freerdp_get_version(int* major, int* minor, int* revision);
FREERDP_API const char* freerdp_get_version_string(void);
FREERDP_API const char* freerdp_get_build_date(void);
FREERDP_API const char* freerdp_get_build_revision(void);
FREERDP_API const char* freerdp_get_build_config(void);
}
function freerdp_new: PFreeRdp; cdecl;
procedure freerdp_free(instance: PFreerdp); cdecl;
{
FREERDP_API BOOL freerdp_focus_required(freerdp* instance);
FREERDP_API void freerdp_set_focus(freerdp* instance);

FREERDP_API int freerdp_get_disconnect_ultimatum(rdpContext* context);
}
function freerdp_get_last_error(context: PRdpContext): UINT32; cdecl;
function freerdp_get_last_error_name(error: UINT32): PAnsiChar; cdecl;
function freerdp_get_last_error_string(error: UINT32): PAnsiChar; cdecl;
{
FREERDP_API void freerdp_set_last_error(rdpContext* context, UINT32 lastError);

FREERDP_API const char* freerdp_get_logon_error_info_type(UINT32 type);
FREERDP_API const char* freerdp_get_logon_error_info_data(UINT32 data);

FREERDP_API ULONG freerdp_get_transport_sent(rdpContext* context,
        BOOL resetCount);

FREERDP_API BOOL freerdp_nla_impersonate(rdpContext* context);
FREERDP_API BOOL freerdp_nla_revert_to_self(rdpContext* context);

FREERDP_API void clearChannelError(rdpContext* context);
FREERDP_API HANDLE getChannelErrorEventHandle(rdpContext* context);
FREERDP_API UINT getChannelError(rdpContext* context);
FREERDP_API const char* getChannelErrorDescription(rdpContext* context);
FREERDP_API void setChannelError(rdpContext* context, UINT errorNum,
                                 char* description);
FREERDP_API BOOL checkChannelErrorEvent(rdpContext* context);

FREERDP_API const char* freerdp_nego_get_routing_token(rdpContext* context, DWORD* length);
}

function freerdp_settings_get_string(settings: PRdpSettings; id: size_t): PAnsiChar; cdecl;
function freerdp_settings_set_string(settings: PRdpSettings; id: size_t; const param: PAnsiChar): BOOL; cdecl;

type
  TFuncBool0 = function: BOOL; cdecl;
  TProc0 = procedure; cdecl;
  TFuncCtxInt = function(ctx: PRdpContext): Integer; cdecl;

procedure IfCall(func: TFuncBool0); overload;
procedure IfCall(proc: TProc0); overload;
function IfCallResult(ADefault: Integer; AFunc: TFuncCtxInt; ACtx: PRdpContext): Integer;

procedure RdpSettingsSet(settings: PRdpSettings; Id: Integer; A: AnsiString);

function FormatRdpError(ACode: UINT32): string;

function MAKE_FREERDP_ERROR(_class, _type: Cardinal): Cardinal;
function GET_FREERDP_ERROR_CLASS(_errorCode: Cardinal): Cardinal;
function GET_FREERDP_ERROR_TYPE(_errorCode: Cardinal): Cardinal;

implementation

function freerdp_connect; external LIBFREERDP_DLL;
function freerdp_abort_connect; external LIBFREERDP_DLL;
function freerdp_shall_disconnect; external LIBFREERDP_DLL;
function freerdp_disconnect; external LIBFREERDP_DLL;

function freerdp_context_new; external LIBFREERDP_DLL;
procedure freerdp_context_free; external LIBFREERDP_DLL;

function freerdp_new; external LIBFREERDP_DLL;
procedure freerdp_free; external LIBFREERDP_DLL;

function freerdp_get_last_error; external LIBFREERDP_DLL;
function freerdp_get_last_error_name; external LIBFREERDP_DLL;
function freerdp_get_last_error_string; external LIBFREERDP_DLL;

function freerdp_settings_get_string; external LIBFREERDP_DLL;
function freerdp_settings_set_string; external LIBFREERDP_DLL;


procedure IfCall(func: TFuncBool0);
begin
  if Assigned(func) then
    func()
end;

procedure IfCall(proc: TProc0);
begin
  if Assigned(proc) then
    proc()
end;

function IfCallResult(ADefault: Integer; AFunc: TFuncCtxInt; ACtx: PRdpContext): Integer;
begin
  if Assigned(AFunc) then
    Result := AFunc(ACtx)
  else
    Result := ADefault
end;

procedure RdpSettingsSet(settings: PRdpSettings; Id: Integer; A: AnsiString);
begin
  Assert(freerdp_settings_set_string(settings, Id, PAnsiChar(A)), 'rdp_settings_set ' + Id.ToString);
end;

function FormatRdpError(ACode: UINT32): string;
begin
  Result := Format('#%d %s %s', [ACode, freerdp_get_last_error_name(ACode), freerdp_get_last_error_string(ACode)])
end;


function MAKE_FREERDP_ERROR(_class, _type: Cardinal): Cardinal;
begin
  Result := (_class shl 16) or _type
end;

function GET_FREERDP_ERROR_CLASS(_errorCode: Cardinal): Cardinal;
begin
  Result := (_errorCode shr 16) and $FFFF
end;

function GET_FREERDP_ERROR_TYPE(_errorCode: Cardinal): Cardinal;
begin
	Result := _errorCode and $FFFF
end;

end.
