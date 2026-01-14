package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerNetapi32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["netapi32.dll"]
	if !ok {
		return
	}
	_ = dll

	d.RegisterAutoStubHandler(dll, "DsAddressToSiteNamesA", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		EntryCount := ctx.Arg(1)
		SocketAddresses := ctx.Arg(2)
		SiteNames := ctx.Arg(3)
		_ = ComputerName
		_ = EntryCount
		_ = SocketAddresses
		_ = SiteNames
		ravelog.Logf("[netapi32] DsAddressToSiteNamesA ComputerName=0x%x EntryCount=0x%x SocketAddresses=0x%x SiteNames=0x%x\n", ComputerName, EntryCount, SocketAddresses, SiteNames)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsAddressToSiteNamesExA", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		EntryCount := ctx.Arg(1)
		SocketAddresses := ctx.Arg(2)
		SiteNames := ctx.Arg(3)
		SubnetNames := ctx.Arg(4)
		_ = ComputerName
		_ = EntryCount
		_ = SocketAddresses
		_ = SiteNames
		_ = SubnetNames
		ravelog.Logf("[netapi32] DsAddressToSiteNamesExA ComputerName=0x%x EntryCount=0x%x SocketAddresses=0x%x SiteNames=0x%x SubnetNames=0x%x\n", ComputerName, EntryCount, SocketAddresses, SiteNames, SubnetNames)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsAddressToSiteNamesExW", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		EntryCount := ctx.Arg(1)
		SocketAddresses := ctx.Arg(2)
		SiteNames := ctx.Arg(3)
		SubnetNames := ctx.Arg(4)
		_ = ComputerName
		_ = EntryCount
		_ = SocketAddresses
		_ = SiteNames
		_ = SubnetNames
		ravelog.Logf("[netapi32] DsAddressToSiteNamesExW ComputerName=0x%x EntryCount=0x%x SocketAddresses=0x%x SiteNames=0x%x SubnetNames=0x%x\n", ComputerName, EntryCount, SocketAddresses, SiteNames, SubnetNames)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsAddressToSiteNamesW", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		EntryCount := ctx.Arg(1)
		SocketAddresses := ctx.Arg(2)
		SiteNames := ctx.Arg(3)
		_ = ComputerName
		_ = EntryCount
		_ = SocketAddresses
		_ = SiteNames
		ravelog.Logf("[netapi32] DsAddressToSiteNamesW ComputerName=0x%x EntryCount=0x%x SocketAddresses=0x%x SiteNames=0x%x\n", ComputerName, EntryCount, SocketAddresses, SiteNames)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsDeregisterDnsHostRecordsA", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		DnsDomainName := ctx.Arg(1)
		DomainGuid := ctx.Arg(2)
		DsaGuid := ctx.Arg(3)
		DnsHostName := ctx.Arg(4)
		_ = ServerName
		_ = DnsDomainName
		_ = DomainGuid
		_ = DsaGuid
		_ = DnsHostName
		ravelog.Logf("[netapi32] DsDeregisterDnsHostRecordsA ServerName=0x%x DnsDomainName=0x%x DomainGuid=0x%x DsaGuid=0x%x DnsHostName=0x%x\n", ServerName, DnsDomainName, DomainGuid, DsaGuid, DnsHostName)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsDeregisterDnsHostRecordsW", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		DnsDomainName := ctx.Arg(1)
		DomainGuid := ctx.Arg(2)
		DsaGuid := ctx.Arg(3)
		DnsHostName := ctx.Arg(4)
		_ = ServerName
		_ = DnsDomainName
		_ = DomainGuid
		_ = DsaGuid
		_ = DnsHostName
		ravelog.Logf("[netapi32] DsDeregisterDnsHostRecordsW ServerName=0x%x DnsDomainName=0x%x DomainGuid=0x%x DsaGuid=0x%x DnsHostName=0x%x\n", ServerName, DnsDomainName, DomainGuid, DsaGuid, DnsHostName)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsEnumerateDomainTrustsA", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		Flags := ctx.Arg(1)
		Domains := ctx.Arg(2)
		DomainCount := ctx.Arg(3)
		_ = ServerName
		_ = Flags
		_ = Domains
		_ = DomainCount
		ravelog.Logf("[netapi32] DsEnumerateDomainTrustsA ServerName=0x%x Flags=0x%x Domains=0x%x DomainCount=0x%x\n", ServerName, Flags, Domains, DomainCount)
		// ERROR_SUCCESS/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsEnumerateDomainTrustsW", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		Flags := ctx.Arg(1)
		Domains := ctx.Arg(2)
		DomainCount := ctx.Arg(3)
		_ = ServerName
		_ = Flags
		_ = Domains
		_ = DomainCount
		ravelog.Logf("[netapi32] DsEnumerateDomainTrustsW ServerName=0x%x Flags=0x%x Domains=0x%x DomainCount=0x%x\n", ServerName, Flags, Domains, DomainCount)
		// ERROR_SUCCESS/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsGetDcNameA", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		DomainName := ctx.Arg(1)
		DomainGuid := ctx.Arg(2)
		SiteName := ctx.Arg(3)
		Flags := ctx.Arg(4)
		DomainControllerInfo := ctx.Arg(5)
		_ = ComputerName
		_ = DomainName
		_ = DomainGuid
		_ = SiteName
		_ = Flags
		_ = DomainControllerInfo
		ravelog.Logf("[netapi32] DsGetDcNameA ComputerName=0x%x DomainName=0x%x DomainGuid=0x%x SiteName=0x%x Flags=0x%x DomainControllerInfo=0x%x\n", ComputerName, DomainName, DomainGuid, SiteName, Flags, DomainControllerInfo)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsGetDcNameW", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		DomainName := ctx.Arg(1)
		DomainGuid := ctx.Arg(2)
		SiteName := ctx.Arg(3)
		Flags := ctx.Arg(4)
		DomainControllerInfo := ctx.Arg(5)
		_ = ComputerName
		_ = DomainName
		_ = DomainGuid
		_ = SiteName
		_ = Flags
		_ = DomainControllerInfo
		ravelog.Logf("[netapi32] DsGetDcNameW ComputerName=0x%x DomainName=0x%x DomainGuid=0x%x SiteName=0x%x Flags=0x%x DomainControllerInfo=0x%x\n", ComputerName, DomainName, DomainGuid, SiteName, Flags, DomainControllerInfo)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsGetDcNameWithAccountA", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		AccountName := ctx.Arg(1)
		AllowableAccountControlBits := ctx.Arg(2)
		DomainName := ctx.Arg(3)
		DomainGuid := ctx.Arg(4)
		SiteName := ctx.Arg(5)
		_ = ComputerName
		_ = AccountName
		_ = AllowableAccountControlBits
		_ = DomainName
		_ = DomainGuid
		_ = SiteName
		ravelog.Logf("[netapi32] DsGetDcNameWithAccountA ComputerName=0x%x AccountName=0x%x AllowableAccountControlBits=0x%x DomainName=0x%x DomainGuid=0x%x SiteName=0x%x\n", ComputerName, AccountName, AllowableAccountControlBits, DomainName, DomainGuid, SiteName)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsGetDcNameWithAccountW", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		AccountName := ctx.Arg(1)
		AllowableAccountControlBits := ctx.Arg(2)
		DomainName := ctx.Arg(3)
		DomainGuid := ctx.Arg(4)
		SiteName := ctx.Arg(5)
		_ = ComputerName
		_ = AccountName
		_ = AllowableAccountControlBits
		_ = DomainName
		_ = DomainGuid
		_ = SiteName
		ravelog.Logf("[netapi32] DsGetDcNameWithAccountW ComputerName=0x%x AccountName=0x%x AllowableAccountControlBits=0x%x DomainName=0x%x DomainGuid=0x%x SiteName=0x%x\n", ComputerName, AccountName, AllowableAccountControlBits, DomainName, DomainGuid, SiteName)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsGetDcSiteCoverageA", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		EntryCount := ctx.Arg(1)
		SiteNames := ctx.Arg(2)
		_ = ServerName
		_ = EntryCount
		_ = SiteNames
		ravelog.Logf("[netapi32] DsGetDcSiteCoverageA ServerName=0x%x EntryCount=0x%x SiteNames=0x%x\n", ServerName, EntryCount, SiteNames)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsGetDcSiteCoverageW", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		EntryCount := ctx.Arg(1)
		SiteNames := ctx.Arg(2)
		_ = ServerName
		_ = EntryCount
		_ = SiteNames
		ravelog.Logf("[netapi32] DsGetDcSiteCoverageW ServerName=0x%x EntryCount=0x%x SiteNames=0x%x\n", ServerName, EntryCount, SiteNames)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsGetForestTrustInformationW", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		TrustedDomainName := ctx.Arg(1)
		Flags := ctx.Arg(2)
		ForestTrustInfo := ctx.Arg(3)
		_ = ServerName
		_ = TrustedDomainName
		_ = Flags
		_ = ForestTrustInfo
		ravelog.Logf("[netapi32] DsGetForestTrustInformationW ServerName=0x%x TrustedDomainName=0x%x Flags=0x%x ForestTrustInfo=0x%x\n", ServerName, TrustedDomainName, Flags, ForestTrustInfo)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsGetSiteNameA", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		SiteName := ctx.Arg(1)
		_ = ComputerName
		_ = SiteName
		ravelog.Logf("[netapi32] DsGetSiteNameA ComputerName=0x%x SiteName=0x%x\n", ComputerName, SiteName)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsGetSiteNameW", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		SiteName := ctx.Arg(1)
		_ = ComputerName
		_ = SiteName
		ravelog.Logf("[netapi32] DsGetSiteNameW ComputerName=0x%x SiteName=0x%x\n", ComputerName, SiteName)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsMergeForestTrustInformationW", func(ctx *ntapi.TrapContext) uint32 {
		DomainName := ctx.Arg(0)
		NewForestTrustInfo := ctx.Arg(1)
		OldForestTrustInfo := ctx.Arg(2)
		MergedForestTrustInfo := ctx.Arg(3)
		_ = DomainName
		_ = NewForestTrustInfo
		_ = OldForestTrustInfo
		_ = MergedForestTrustInfo
		ravelog.Logf("[netapi32] DsMergeForestTrustInformationW DomainName=0x%x NewForestTrustInfo=0x%x OldForestTrustInfo=0x%x MergedForestTrustInfo=0x%x\n", DomainName, NewForestTrustInfo, OldForestTrustInfo, MergedForestTrustInfo)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsRoleFreeMemory", func(ctx *ntapi.TrapContext) uint32 {
		Buffer := ctx.Arg(0)
		_ = Buffer
		ravelog.Logf("[netapi32] DsRoleFreeMemory Buffer=0x%x\n", Buffer)
		// void/0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsRoleGetPrimaryDomainInformation", func(ctx *ntapi.TrapContext) uint32 {
		lpServer := ctx.Arg(0)
		InfoLevel := ctx.Arg(1)
		Buffer := ctx.Arg(2)
		_ = lpServer
		_ = InfoLevel
		_ = Buffer
		ravelog.Logf("[netapi32] DsRoleGetPrimaryDomainInformation lpServer=0x%x InfoLevel=0x%x Buffer=0x%x\n", lpServer, InfoLevel, Buffer)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsValidateSubnetNameA", func(ctx *ntapi.TrapContext) uint32 {
		SubnetName := ctx.Arg(0)
		_ = SubnetName
		ravelog.Logf("[netapi32] DsValidateSubnetNameA SubnetName=0x%x\n", SubnetName)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DsValidateSubnetNameW", func(ctx *ntapi.TrapContext) uint32 {
		SubnetName := ctx.Arg(0)
		_ = SubnetName
		ravelog.Logf("[netapi32] DsValidateSubnetNameW SubnetName=0x%x\n", SubnetName)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_BrowserDebugTrace", func(ctx *ntapi.TrapContext) uint32 {
		Server := ctx.Arg(0)
		TraceString := ctx.Arg(1)
		_ = Server
		_ = TraceString
		ravelog.Logf("[netapi32] I_BrowserDebugTrace Server=0x%x TraceString=0x%x\n", Server, TraceString)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_BrowserQueryEmulatedDomains", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		EmulatedDomains := ctx.Arg(1)
		EntriesRead := ctx.Arg(2)
		_ = ServerName
		_ = EmulatedDomains
		_ = EntriesRead
		ravelog.Logf("[netapi32] I_BrowserQueryEmulatedDomains ServerName=0x%x EmulatedDomains=0x%x EntriesRead=0x%x\n", ServerName, EmulatedDomains, EntriesRead)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_BrowserQueryOtherDomains", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		OtherDomains := ctx.Arg(1)
		EntriesRead := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = ServerName
		_ = OtherDomains
		_ = EntriesRead
		_ = arg3
		ravelog.Logf("[netapi32] I_BrowserQueryOtherDomains ServerName=0x%x OtherDomains=0x%x EntriesRead=0x%x arg3=0x%x\n", ServerName, OtherDomains, EntriesRead, arg3)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_BrowserQueryStatistics", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		Statistics := ctx.Arg(1)
		_ = ServerName
		_ = Statistics
		ravelog.Logf("[netapi32] I_BrowserQueryStatistics ServerName=0x%x Statistics=0x%x\n", ServerName, Statistics)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_BrowserResetNetlogonState", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		_ = ServerName
		ravelog.Logf("[netapi32] I_BrowserResetNetlogonState ServerName=0x%x\n", ServerName)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_BrowserResetStatistics", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		_ = ServerName
		ravelog.Logf("[netapi32] I_BrowserResetStatistics ServerName=0x%x\n", ServerName)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_BrowserServerEnum", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		Transport := ctx.Arg(1)
		ClientName := ctx.Arg(2)
		Level := ctx.Arg(3)
		BufPtr := ctx.Arg(4)
		PrefMaxLen := ctx.Arg(5)
		_ = ServerName
		_ = Transport
		_ = ClientName
		_ = Level
		_ = BufPtr
		_ = PrefMaxLen
		ravelog.Logf("[netapi32] I_BrowserServerEnum ServerName=0x%x Transport=0x%x ClientName=0x%x Level=0x%x BufPtr=0x%x PrefMaxLen=0x%x\n", ServerName, Transport, ClientName, Level, BufPtr, PrefMaxLen)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_BrowserSetNetlogonState", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		DomainName := ctx.Arg(1)
		EmulatedServerName := ctx.Arg(2)
		NewRole := ctx.Arg(3)
		_ = ServerName
		_ = DomainName
		_ = EmulatedServerName
		_ = NewRole
		ravelog.Logf("[netapi32] I_BrowserSetNetlogonState ServerName=0x%x DomainName=0x%x EmulatedServerName=0x%x NewRole=0x%x\n", ServerName, DomainName, EmulatedServerName, NewRole)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_NetNameCompare", func(ctx *ntapi.TrapContext) uint32 {
		Reserved := ctx.Arg(0)
		Name1 := ctx.Arg(1)
		Name2 := ctx.Arg(2)
		NameType := ctx.Arg(3)
		Flags := ctx.Arg(4)
		_ = Reserved
		_ = Name1
		_ = Name2
		_ = NameType
		_ = Flags
		ravelog.Logf("[netapi32] I_NetNameCompare Reserved=0x%x Name1=0x%x Name2=0x%x NameType=0x%x Flags=0x%x\n", Reserved, Name1, Name2, NameType, Flags)
		// 0/equal
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_NetNameValidate", func(ctx *ntapi.TrapContext) uint32 {
		Reserved := ctx.Arg(0)
		Name := ctx.Arg(1)
		NameType := ctx.Arg(2)
		Flags := ctx.Arg(3)
		_ = Reserved
		_ = Name
		_ = NameType
		_ = Flags
		ravelog.Logf("[netapi32] I_NetNameValidate Reserved=0x%x Name=0x%x NameType=0x%x Flags=0x%x\n", Reserved, Name, NameType, Flags)
		// NERR_Success/valid
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "I_NetServerSetServiceBits", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		TransportName := ctx.Arg(1)
		ServiceBits := ctx.Arg(2)
		UpdateImmediately := ctx.Arg(3)
		_ = ServerName
		_ = TransportName
		_ = ServiceBits
		_ = UpdateImmediately
		ravelog.Logf("[netapi32] I_NetServerSetServiceBits ServerName=0x%x TransportName=0x%x ServiceBits=0x%x UpdateImmediately=0x%x\n", ServerName, TransportName, ServiceBits, UpdateImmediately)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetAddAlternateComputerName", func(ctx *ntapi.TrapContext) uint32 {
		Server := ctx.Arg(0)
		AlternateName := ctx.Arg(1)
		DomainAccount := ctx.Arg(2)
		DomainAccountPassword := ctx.Arg(3)
		Reserved := ctx.Arg(4)
		_ = Server
		_ = AlternateName
		_ = DomainAccount
		_ = DomainAccountPassword
		_ = Reserved
		ravelog.Logf("[netapi32] NetAddAlternateComputerName Server=0x%x AlternateName=0x%x DomainAccount=0x%x DomainAccountPassword=0x%x Reserved=0x%x\n", Server, AlternateName, DomainAccount, DomainAccountPassword, Reserved)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetAlertRaise", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		_ = arg0
		_ = arg1
		_ = arg2
		ravelog.Logf("[netapi32] NetAlertRaise arg0=0x%x arg1=0x%x arg2=0x%x\n", arg0, arg1, arg2)
		// NERR_Success/ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetAlertRaiseEx", func(ctx *ntapi.TrapContext) uint32 {
		arg0 := ctx.Arg(0)
		arg1 := ctx.Arg(1)
		arg2 := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = arg0
		_ = arg1
		_ = arg2
		_ = arg3
		ravelog.Logf("[netapi32] NetAlertRaiseEx arg0=0x%x arg1=0x%x arg2=0x%x arg3=0x%x\n", arg0, arg1, arg2, arg3)
		// NERR_Success/ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetApiBufferAllocate", func(ctx *ntapi.TrapContext) uint32 {
		ByteCount := ctx.Arg(0)
		Buffer := ctx.Arg(1)
		_ = ByteCount
		_ = Buffer
		ravelog.Logf("[netapi32] NetApiBufferAllocate ByteCount=0x%x Buffer=0x%x\n", ByteCount, Buffer)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetApiBufferFree", func(ctx *ntapi.TrapContext) uint32 {
		Buffer := ctx.Arg(0)
		_ = Buffer
		ravelog.Logf("[netapi32] NetApiBufferFree Buffer=0x%x\n", Buffer)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetApiBufferReallocate", func(ctx *ntapi.TrapContext) uint32 {
		OldBuffer := ctx.Arg(0)
		NewByteCount := ctx.Arg(1)
		NewBuffer := ctx.Arg(2)
		_ = OldBuffer
		_ = NewByteCount
		_ = NewBuffer
		ravelog.Logf("[netapi32] NetApiBufferReallocate OldBuffer=0x%x NewByteCount=0x%x NewBuffer=0x%x\n", OldBuffer, NewByteCount, NewBuffer)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetApiBufferSize", func(ctx *ntapi.TrapContext) uint32 {
		Buffer := ctx.Arg(0)
		ByteCount := ctx.Arg(1)
		_ = Buffer
		_ = ByteCount
		ravelog.Logf("[netapi32] NetApiBufferSize Buffer=0x%x ByteCount=0x%x\n", Buffer, ByteCount)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetAuditClear", func(ctx *ntapi.TrapContext) uint32 {
		server := ctx.Arg(0)
		backupfile := ctx.Arg(1)
		service := ctx.Arg(2)
		_ = server
		_ = backupfile
		_ = service
		ravelog.Logf("[netapi32] NetAuditClear server=0x%x backupfile=0x%x service=0x%x\n", server, backupfile, service)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetAuditRead", func(ctx *ntapi.TrapContext) uint32 {
		server := ctx.Arg(0)
		service := ctx.Arg(1)
		auditloghandle := ctx.Arg(2)
		offset := ctx.Arg(3)
		reserved1 := ctx.Arg(4)
		reserved2 := ctx.Arg(5)
		_ = server
		_ = service
		_ = auditloghandle
		_ = offset
		_ = reserved1
		_ = reserved2
		ravelog.Logf("[netapi32] NetAuditRead server=0x%x service=0x%x auditloghandle=0x%x offset=0x%x reserved1=0x%x reserved2=0x%x\n", server, service, auditloghandle, offset, reserved1, reserved2)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetAuditWrite", func(ctx *ntapi.TrapContext) uint32 {
		msgType := ctx.Arg(0)
		buf := ctx.Arg(1)
		numbytes := ctx.Arg(2)
		service := ctx.Arg(3)
		reserved := ctx.Arg(4)
		_ = msgType
		_ = buf
		_ = numbytes
		_ = service
		_ = reserved
		ravelog.Logf("[netapi32] NetAuditWrite msgType=0x%x buf=0x%x numbytes=0x%x service=0x%x reserved=0x%x\n", msgType, buf, numbytes, service, reserved)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetBrowserStatisticsGet", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = servername
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetBrowserStatisticsGet servername=0x%x level=0x%x bufptr=0x%x\n", servername, level, bufptr)
		// NERR_InvalidComputer
		ctx.SetReturn(2351)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetConfigGet", func(ctx *ntapi.TrapContext) uint32 {
		server := ctx.Arg(0)
		component := ctx.Arg(1)
		parameter := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = server
		_ = component
		_ = parameter
		_ = bufptr
		ravelog.Logf("[netapi32] NetConfigGet server=0x%x component=0x%x parameter=0x%x bufptr=0x%x\n", server, component, parameter, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetConfigGetAll", func(ctx *ntapi.TrapContext) uint32 {
		server := ctx.Arg(0)
		component := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = server
		_ = component
		_ = bufptr
		ravelog.Logf("[netapi32] NetConfigGetAll server=0x%x component=0x%x bufptr=0x%x\n", server, component, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetConfigSet", func(ctx *ntapi.TrapContext) uint32 {
		server := ctx.Arg(0)
		reserved1 := ctx.Arg(1)
		component := ctx.Arg(2)
		reserved2 := ctx.Arg(3)
		reserved3 := ctx.Arg(4)
		parameter := ctx.Arg(5)
		_ = server
		_ = reserved1
		_ = component
		_ = reserved2
		_ = reserved3
		_ = parameter
		ravelog.Logf("[netapi32] NetConfigSet server=0x%x reserved1=0x%x component=0x%x reserved2=0x%x reserved3=0x%x parameter=0x%x\n", server, reserved1, component, reserved2, reserved3, parameter)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetConnectionEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		qualifier := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		prefmaxlen := ctx.Arg(4)
		entriesread := ctx.Arg(5)
		_ = servername
		_ = qualifier
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		ravelog.Logf("[netapi32] NetConnectionEnum servername=0x%x qualifier=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x\n", servername, qualifier, level, bufptr, prefmaxlen, entriesread)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsAdd", func(ctx *ntapi.TrapContext) uint32 {
		DfsEntryPath := ctx.Arg(0)
		ServerName := ctx.Arg(1)
		ShareName := ctx.Arg(2)
		Comment := ctx.Arg(3)
		Flags := ctx.Arg(4)
		_ = DfsEntryPath
		_ = ServerName
		_ = ShareName
		_ = Comment
		_ = Flags
		ravelog.Logf("[netapi32] NetDfsAdd DfsEntryPath=0x%x ServerName=0x%x ShareName=0x%x Comment=0x%x Flags=0x%x\n", DfsEntryPath, ServerName, ShareName, Comment, Flags)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsAddFtRoot", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		RootShare := ctx.Arg(1)
		FtDfsName := ctx.Arg(2)
		Comment := ctx.Arg(3)
		Flags := ctx.Arg(4)
		_ = ServerName
		_ = RootShare
		_ = FtDfsName
		_ = Comment
		_ = Flags
		ravelog.Logf("[netapi32] NetDfsAddFtRoot ServerName=0x%x RootShare=0x%x FtDfsName=0x%x Comment=0x%x Flags=0x%x\n", ServerName, RootShare, FtDfsName, Comment, Flags)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsAddStdRoot", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		RootShare := ctx.Arg(1)
		Comment := ctx.Arg(2)
		Flags := ctx.Arg(3)
		_ = ServerName
		_ = RootShare
		_ = Comment
		_ = Flags
		ravelog.Logf("[netapi32] NetDfsAddStdRoot ServerName=0x%x RootShare=0x%x Comment=0x%x Flags=0x%x\n", ServerName, RootShare, Comment, Flags)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsAddStdRootForced", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		RootShare := ctx.Arg(1)
		Comment := ctx.Arg(2)
		Store := ctx.Arg(3)
		_ = ServerName
		_ = RootShare
		_ = Comment
		_ = Store
		ravelog.Logf("[netapi32] NetDfsAddStdRootForced ServerName=0x%x RootShare=0x%x Comment=0x%x Store=0x%x\n", ServerName, RootShare, Comment, Store)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsEnum", func(ctx *ntapi.TrapContext) uint32 {
		DfsName := ctx.Arg(0)
		Level := ctx.Arg(1)
		PrefMaxLen := ctx.Arg(2)
		Buffer := ctx.Arg(3)
		EntriesRead := ctx.Arg(4)
		ResumeHandle := ctx.Arg(5)
		_ = DfsName
		_ = Level
		_ = PrefMaxLen
		_ = Buffer
		_ = EntriesRead
		_ = ResumeHandle
		ravelog.Logf("[netapi32] NetDfsEnum DfsName=0x%x Level=0x%x PrefMaxLen=0x%x Buffer=0x%x EntriesRead=0x%x ResumeHandle=0x%x\n", DfsName, Level, PrefMaxLen, Buffer, EntriesRead, ResumeHandle)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsGetClientInfo", func(ctx *ntapi.TrapContext) uint32 {
		DfsEntryPath := ctx.Arg(0)
		ServerName := ctx.Arg(1)
		ShareName := ctx.Arg(2)
		Level := ctx.Arg(3)
		Buffer := ctx.Arg(4)
		_ = DfsEntryPath
		_ = ServerName
		_ = ShareName
		_ = Level
		_ = Buffer
		ravelog.Logf("[netapi32] NetDfsGetClientInfo DfsEntryPath=0x%x ServerName=0x%x ShareName=0x%x Level=0x%x Buffer=0x%x\n", DfsEntryPath, ServerName, ShareName, Level, Buffer)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsGetDcAddress", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		DcIpAddress := ctx.Arg(1)
		IsSysvol := ctx.Arg(2)
		Timeout := ctx.Arg(3)
		_ = ServerName
		_ = DcIpAddress
		_ = IsSysvol
		_ = Timeout
		ravelog.Logf("[netapi32] NetDfsGetDcAddress ServerName=0x%x DcIpAddress=0x%x IsSysvol=0x%x Timeout=0x%x\n", ServerName, DcIpAddress, IsSysvol, Timeout)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsGetFtContainerSecurity", func(ctx *ntapi.TrapContext) uint32 {
		DomainName := ctx.Arg(0)
		SecurityInformation := ctx.Arg(1)
		ppSecurityDescriptor := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = DomainName
		_ = SecurityInformation
		_ = ppSecurityDescriptor
		_ = arg3
		ravelog.Logf("[netapi32] NetDfsGetFtContainerSecurity DomainName=0x%x SecurityInformation=0x%x ppSecurityDescriptor=0x%x arg3=0x%x\n", DomainName, SecurityInformation, ppSecurityDescriptor, arg3)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		DfsEntryPath := ctx.Arg(0)
		ServerName := ctx.Arg(1)
		ShareName := ctx.Arg(2)
		Level := ctx.Arg(3)
		Buffer := ctx.Arg(4)
		_ = DfsEntryPath
		_ = ServerName
		_ = ShareName
		_ = Level
		_ = Buffer
		ravelog.Logf("[netapi32] NetDfsGetInfo DfsEntryPath=0x%x ServerName=0x%x ShareName=0x%x Level=0x%x Buffer=0x%x\n", DfsEntryPath, ServerName, ShareName, Level, Buffer)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsGetSecurity", func(ctx *ntapi.TrapContext) uint32 {
		DfsEntryPath := ctx.Arg(0)
		SecurityInformation := ctx.Arg(1)
		ppSecurityDescriptor := ctx.Arg(2)
		lpcbSecurityDescriptor := ctx.Arg(3)
		_ = DfsEntryPath
		_ = SecurityInformation
		_ = ppSecurityDescriptor
		_ = lpcbSecurityDescriptor
		ravelog.Logf("[netapi32] NetDfsGetSecurity DfsEntryPath=0x%x SecurityInformation=0x%x ppSecurityDescriptor=0x%x lpcbSecurityDescriptor=0x%x\n", DfsEntryPath, SecurityInformation, ppSecurityDescriptor, lpcbSecurityDescriptor)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsGetStdContainerSecurity", func(ctx *ntapi.TrapContext) uint32 {
		MachineName := ctx.Arg(0)
		SecurityInformation := ctx.Arg(1)
		ppSecurityDescriptor := ctx.Arg(2)
		arg3 := ctx.Arg(3)
		_ = MachineName
		_ = SecurityInformation
		_ = ppSecurityDescriptor
		_ = arg3
		ravelog.Logf("[netapi32] NetDfsGetStdContainerSecurity MachineName=0x%x SecurityInformation=0x%x ppSecurityDescriptor=0x%x arg3=0x%x\n", MachineName, SecurityInformation, ppSecurityDescriptor, arg3)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsManagerInitialize", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		Flags := ctx.Arg(1)
		_ = ServerName
		_ = Flags
		ravelog.Logf("[netapi32] NetDfsManagerInitialize ServerName=0x%x Flags=0x%x\n", ServerName, Flags)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsMove", func(ctx *ntapi.TrapContext) uint32 {
		OldDfsEntryPath := ctx.Arg(0)
		NewDfsEntryPath := ctx.Arg(1)
		Flags := ctx.Arg(2)
		_ = OldDfsEntryPath
		_ = NewDfsEntryPath
		_ = Flags
		ravelog.Logf("[netapi32] NetDfsMove OldDfsEntryPath=0x%x NewDfsEntryPath=0x%x Flags=0x%x\n", OldDfsEntryPath, NewDfsEntryPath, Flags)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsRemove", func(ctx *ntapi.TrapContext) uint32 {
		DfsEntryPath := ctx.Arg(0)
		ServerName := ctx.Arg(1)
		ShareName := ctx.Arg(2)
		_ = DfsEntryPath
		_ = ServerName
		_ = ShareName
		ravelog.Logf("[netapi32] NetDfsRemove DfsEntryPath=0x%x ServerName=0x%x ShareName=0x%x\n", DfsEntryPath, ServerName, ShareName)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsRemoveFtRoot", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		RootShare := ctx.Arg(1)
		FtDfsName := ctx.Arg(2)
		Flags := ctx.Arg(3)
		_ = ServerName
		_ = RootShare
		_ = FtDfsName
		_ = Flags
		ravelog.Logf("[netapi32] NetDfsRemoveFtRoot ServerName=0x%x RootShare=0x%x FtDfsName=0x%x Flags=0x%x\n", ServerName, RootShare, FtDfsName, Flags)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsRemoveFtRootForced", func(ctx *ntapi.TrapContext) uint32 {
		DomainName := ctx.Arg(0)
		ServerName := ctx.Arg(1)
		RootShare := ctx.Arg(2)
		FtDfsName := ctx.Arg(3)
		Flags := ctx.Arg(4)
		_ = DomainName
		_ = ServerName
		_ = RootShare
		_ = FtDfsName
		_ = Flags
		ravelog.Logf("[netapi32] NetDfsRemoveFtRootForced DomainName=0x%x ServerName=0x%x RootShare=0x%x FtDfsName=0x%x Flags=0x%x\n", DomainName, ServerName, RootShare, FtDfsName, Flags)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsRemoveStdRoot", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		RootShare := ctx.Arg(1)
		Flags := ctx.Arg(2)
		_ = ServerName
		_ = RootShare
		_ = Flags
		ravelog.Logf("[netapi32] NetDfsRemoveStdRoot ServerName=0x%x RootShare=0x%x Flags=0x%x\n", ServerName, RootShare, Flags)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsRename", func(ctx *ntapi.TrapContext) uint32 {
		Path := ctx.Arg(0)
		NewPath := ctx.Arg(1)
		_ = Path
		_ = NewPath
		ravelog.Logf("[netapi32] NetDfsRename Path=0x%x NewPath=0x%x\n", Path, NewPath)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsSetClientInfo", func(ctx *ntapi.TrapContext) uint32 {
		DfsEntryPath := ctx.Arg(0)
		ServerName := ctx.Arg(1)
		ShareName := ctx.Arg(2)
		Level := ctx.Arg(3)
		Buffer := ctx.Arg(4)
		_ = DfsEntryPath
		_ = ServerName
		_ = ShareName
		_ = Level
		_ = Buffer
		ravelog.Logf("[netapi32] NetDfsSetClientInfo DfsEntryPath=0x%x ServerName=0x%x ShareName=0x%x Level=0x%x Buffer=0x%x\n", DfsEntryPath, ServerName, ShareName, Level, Buffer)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsSetFtContainerSecurity", func(ctx *ntapi.TrapContext) uint32 {
		DomainName := ctx.Arg(0)
		SecurityInformation := ctx.Arg(1)
		pSecurityDescriptor := ctx.Arg(2)
		_ = DomainName
		_ = SecurityInformation
		_ = pSecurityDescriptor
		ravelog.Logf("[netapi32] NetDfsSetFtContainerSecurity DomainName=0x%x SecurityInformation=0x%x pSecurityDescriptor=0x%x\n", DomainName, SecurityInformation, pSecurityDescriptor)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		DfsEntryPath := ctx.Arg(0)
		ServerName := ctx.Arg(1)
		ShareName := ctx.Arg(2)
		Level := ctx.Arg(3)
		Buffer := ctx.Arg(4)
		_ = DfsEntryPath
		_ = ServerName
		_ = ShareName
		_ = Level
		_ = Buffer
		ravelog.Logf("[netapi32] NetDfsSetInfo DfsEntryPath=0x%x ServerName=0x%x ShareName=0x%x Level=0x%x Buffer=0x%x\n", DfsEntryPath, ServerName, ShareName, Level, Buffer)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsSetSecurity", func(ctx *ntapi.TrapContext) uint32 {
		DfsEntryPath := ctx.Arg(0)
		SecurityInformation := ctx.Arg(1)
		pSecurityDescriptor := ctx.Arg(2)
		_ = DfsEntryPath
		_ = SecurityInformation
		_ = pSecurityDescriptor
		ravelog.Logf("[netapi32] NetDfsSetSecurity DfsEntryPath=0x%x SecurityInformation=0x%x pSecurityDescriptor=0x%x\n", DfsEntryPath, SecurityInformation, pSecurityDescriptor)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetDfsSetStdContainerSecurity", func(ctx *ntapi.TrapContext) uint32 {
		MachineName := ctx.Arg(0)
		SecurityInformation := ctx.Arg(1)
		pSecurityDescriptor := ctx.Arg(2)
		_ = MachineName
		_ = SecurityInformation
		_ = pSecurityDescriptor
		ravelog.Logf("[netapi32] NetDfsSetStdContainerSecurity MachineName=0x%x SecurityInformation=0x%x pSecurityDescriptor=0x%x\n", MachineName, SecurityInformation, pSecurityDescriptor)
		// ERROR_NOT_FOUND
		ctx.SetReturn(1168)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetEnumerateComputerNames", func(ctx *ntapi.TrapContext) uint32 {
		Server := ctx.Arg(0)
		NameType := ctx.Arg(1)
		Reserved := ctx.Arg(2)
		EntryCount := ctx.Arg(3)
		ComputerNames := ctx.Arg(4)
		_ = Server
		_ = NameType
		_ = Reserved
		_ = EntryCount
		_ = ComputerNames
		ravelog.Logf("[netapi32] NetEnumerateComputerNames Server=0x%x NameType=0x%x Reserved=0x%x EntryCount=0x%x ComputerNames=0x%x\n", Server, NameType, Reserved, EntryCount, ComputerNames)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetEnumerateTrustedDomains", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		DomainNames := ctx.Arg(1)
		_ = ServerName
		_ = DomainNames
		ravelog.Logf("[netapi32] NetEnumerateTrustedDomains ServerName=0x%x DomainNames=0x%x\n", ServerName, DomainNames)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetErrorLogClear", func(ctx *ntapi.TrapContext) uint32 {
		UncServerName := ctx.Arg(0)
		BackupFile := ctx.Arg(1)
		Reserved := ctx.Arg(2)
		_ = UncServerName
		_ = BackupFile
		_ = Reserved
		ravelog.Logf("[netapi32] NetErrorLogClear UncServerName=0x%x BackupFile=0x%x Reserved=0x%x\n", UncServerName, BackupFile, Reserved)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetErrorLogRead", func(ctx *ntapi.TrapContext) uint32 {
		UncServerName := ctx.Arg(0)
		Reserved1 := ctx.Arg(1)
		ErrorLogHandle := ctx.Arg(2)
		Offset := ctx.Arg(3)
		Reserved2 := ctx.Arg(4)
		Reserved3 := ctx.Arg(5)
		_ = UncServerName
		_ = Reserved1
		_ = ErrorLogHandle
		_ = Offset
		_ = Reserved2
		_ = Reserved3
		ravelog.Logf("[netapi32] NetErrorLogRead UncServerName=0x%x Reserved1=0x%x ErrorLogHandle=0x%x Offset=0x%x Reserved2=0x%x Reserved3=0x%x\n", UncServerName, Reserved1, ErrorLogHandle, Offset, Reserved2, Reserved3)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetErrorLogWrite", func(ctx *ntapi.TrapContext) uint32 {
		Reserved := ctx.Arg(0)
		Code := ctx.Arg(1)
		Component := ctx.Arg(2)
		Buffer := ctx.Arg(3)
		NumBytes := ctx.Arg(4)
		MsgBuf := ctx.Arg(5)
		_ = Reserved
		_ = Code
		_ = Component
		_ = Buffer
		_ = NumBytes
		_ = MsgBuf
		ravelog.Logf("[netapi32] NetErrorLogWrite Reserved=0x%x Code=0x%x Component=0x%x Buffer=0x%x NumBytes=0x%x MsgBuf=0x%x\n", Reserved, Code, Component, Buffer, NumBytes, MsgBuf)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetFileClose", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		fileid := ctx.Arg(1)
		_ = servername
		_ = fileid
		ravelog.Logf("[netapi32] NetFileClose servername=0x%x fileid=0x%x\n", servername, fileid)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetFileEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		basepath := ctx.Arg(1)
		username := ctx.Arg(2)
		level := ctx.Arg(3)
		bufptr := ctx.Arg(4)
		prefmaxlen := ctx.Arg(5)
		_ = servername
		_ = basepath
		_ = username
		_ = level
		_ = bufptr
		_ = prefmaxlen
		ravelog.Logf("[netapi32] NetFileEnum servername=0x%x basepath=0x%x username=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x\n", servername, basepath, username, level, bufptr, prefmaxlen)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetFileGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		fileid := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = servername
		_ = fileid
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetFileGetInfo servername=0x%x fileid=0x%x level=0x%x bufptr=0x%x\n", servername, fileid, level, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGetAnyDCName", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		DomainName := ctx.Arg(1)
		Buffer := ctx.Arg(2)
		_ = ServerName
		_ = DomainName
		_ = Buffer
		ravelog.Logf("[netapi32] NetGetAnyDCName ServerName=0x%x DomainName=0x%x Buffer=0x%x\n", ServerName, DomainName, Buffer)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGetDCName", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		DomainName := ctx.Arg(1)
		Buffer := ctx.Arg(2)
		_ = ServerName
		_ = DomainName
		_ = Buffer
		ravelog.Logf("[netapi32] NetGetDCName ServerName=0x%x DomainName=0x%x Buffer=0x%x\n", ServerName, DomainName, Buffer)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGetDisplayInformationIndex", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		Level := ctx.Arg(1)
		Prefix := ctx.Arg(2)
		Index := ctx.Arg(3)
		_ = ServerName
		_ = Level
		_ = Prefix
		_ = Index
		ravelog.Logf("[netapi32] NetGetDisplayInformationIndex ServerName=0x%x Level=0x%x Prefix=0x%x Index=0x%x\n", ServerName, Level, Prefix, Index)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGetJoinInformation", func(ctx *ntapi.TrapContext) uint32 {
		lpServer := ctx.Arg(0)
		lpNameBuffer := ctx.Arg(1)
		BufferType := ctx.Arg(2)
		_ = lpServer
		_ = lpNameBuffer
		_ = BufferType
		ravelog.Logf("[netapi32] NetGetJoinInformation lpServer=0x%x lpNameBuffer=0x%x BufferType=0x%x\n", lpServer, lpNameBuffer, BufferType)
		// NERR_Success/not joined
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGetJoinableOUs", func(ctx *ntapi.TrapContext) uint32 {
		lpServer := ctx.Arg(0)
		lpDomain := ctx.Arg(1)
		lpAccount := ctx.Arg(2)
		lpPassword := ctx.Arg(3)
		OUCount := ctx.Arg(4)
		OUs := ctx.Arg(5)
		_ = lpServer
		_ = lpDomain
		_ = lpAccount
		_ = lpPassword
		_ = OUCount
		_ = OUs
		ravelog.Logf("[netapi32] NetGetJoinableOUs lpServer=0x%x lpDomain=0x%x lpAccount=0x%x lpPassword=0x%x OUCount=0x%x OUs=0x%x\n", lpServer, lpDomain, lpAccount, lpPassword, OUCount, OUs)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGroupAdd", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetGroupAdd servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGroupAddUser", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		username := ctx.Arg(2)
		_ = servername
		_ = groupname
		_ = username
		ravelog.Logf("[netapi32] NetGroupAddUser servername=0x%x groupname=0x%x username=0x%x\n", servername, groupname, username)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGroupDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		_ = servername
		_ = groupname
		ravelog.Logf("[netapi32] NetGroupDel servername=0x%x groupname=0x%x\n", servername, groupname)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGroupDelUser", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		username := ctx.Arg(2)
		_ = servername
		_ = groupname
		_ = username
		ravelog.Logf("[netapi32] NetGroupDelUser servername=0x%x groupname=0x%x username=0x%x\n", servername, groupname, username)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGroupEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetGroupEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGroupGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = servername
		_ = groupname
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetGroupGetInfo servername=0x%x groupname=0x%x level=0x%x bufptr=0x%x\n", servername, groupname, level, bufptr)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGroupGetUsers", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		prefmaxlen := ctx.Arg(4)
		entriesread := ctx.Arg(5)
		_ = servername
		_ = groupname
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		ravelog.Logf("[netapi32] NetGroupGetUsers servername=0x%x groupname=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x\n", servername, groupname, level, bufptr, prefmaxlen, entriesread)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGroupSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		parm_err := ctx.Arg(4)
		_ = servername
		_ = groupname
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetGroupSetInfo servername=0x%x groupname=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, groupname, level, buf, parm_err)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetGroupSetUsers", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		totalentries := ctx.Arg(4)
		_ = servername
		_ = groupname
		_ = level
		_ = buf
		_ = totalentries
		ravelog.Logf("[netapi32] NetGroupSetUsers servername=0x%x groupname=0x%x level=0x%x buf=0x%x totalentries=0x%x\n", servername, groupname, level, buf, totalentries)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetJoinDomain", func(ctx *ntapi.TrapContext) uint32 {
		lpServer := ctx.Arg(0)
		lpDomain := ctx.Arg(1)
		lpMachineAccountOU := ctx.Arg(2)
		lpAccount := ctx.Arg(3)
		lpPassword := ctx.Arg(4)
		fJoinOptions := ctx.Arg(5)
		_ = lpServer
		_ = lpDomain
		_ = lpMachineAccountOU
		_ = lpAccount
		_ = lpPassword
		_ = fJoinOptions
		ravelog.Logf("[netapi32] NetJoinDomain lpServer=0x%x lpDomain=0x%x lpMachineAccountOU=0x%x lpAccount=0x%x lpPassword=0x%x fJoinOptions=0x%x\n", lpServer, lpDomain, lpMachineAccountOU, lpAccount, lpPassword, fJoinOptions)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupAdd", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetLocalGroupAdd servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupAddMember", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		membersid := ctx.Arg(2)
		_ = servername
		_ = groupname
		_ = membersid
		ravelog.Logf("[netapi32] NetLocalGroupAddMember servername=0x%x groupname=0x%x membersid=0x%x\n", servername, groupname, membersid)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupAddMembers", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		totalentries := ctx.Arg(4)
		_ = servername
		_ = groupname
		_ = level
		_ = buf
		_ = totalentries
		ravelog.Logf("[netapi32] NetLocalGroupAddMembers servername=0x%x groupname=0x%x level=0x%x buf=0x%x totalentries=0x%x\n", servername, groupname, level, buf, totalentries)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		_ = servername
		_ = groupname
		ravelog.Logf("[netapi32] NetLocalGroupDel servername=0x%x groupname=0x%x\n", servername, groupname)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupDelMember", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		membersid := ctx.Arg(2)
		_ = servername
		_ = groupname
		_ = membersid
		ravelog.Logf("[netapi32] NetLocalGroupDelMember servername=0x%x groupname=0x%x membersid=0x%x\n", servername, groupname, membersid)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupDelMembers", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		totalentries := ctx.Arg(4)
		_ = servername
		_ = groupname
		_ = level
		_ = buf
		_ = totalentries
		ravelog.Logf("[netapi32] NetLocalGroupDelMembers servername=0x%x groupname=0x%x level=0x%x buf=0x%x totalentries=0x%x\n", servername, groupname, level, buf, totalentries)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetLocalGroupEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = servername
		_ = groupname
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetLocalGroupGetInfo servername=0x%x groupname=0x%x level=0x%x bufptr=0x%x\n", servername, groupname, level, bufptr)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupGetMembers", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		localgroupname := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		prefmaxlen := ctx.Arg(4)
		entriesread := ctx.Arg(5)
		_ = servername
		_ = localgroupname
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		ravelog.Logf("[netapi32] NetLocalGroupGetMembers servername=0x%x localgroupname=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x\n", servername, localgroupname, level, bufptr, prefmaxlen, entriesread)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		parm_err := ctx.Arg(4)
		_ = servername
		_ = groupname
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetLocalGroupSetInfo servername=0x%x groupname=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, groupname, level, buf, parm_err)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLocalGroupSetMembers", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		groupname := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		totalentries := ctx.Arg(4)
		_ = servername
		_ = groupname
		_ = level
		_ = buf
		_ = totalentries
		ravelog.Logf("[netapi32] NetLocalGroupSetMembers servername=0x%x groupname=0x%x level=0x%x buf=0x%x totalentries=0x%x\n", servername, groupname, level, buf, totalentries)
		// NERR_GroupNotFound
		ctx.SetReturn(2220)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLogonGetTimeServiceParentDomain", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		DomainName := ctx.Arg(1)
		PdcSameSite := ctx.Arg(2)
		_ = ServerName
		_ = DomainName
		_ = PdcSameSite
		ravelog.Logf("[netapi32] NetLogonGetTimeServiceParentDomain ServerName=0x%x DomainName=0x%x PdcSameSite=0x%x\n", ServerName, DomainName, PdcSameSite)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetLogonSetServiceBits", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		ServiceBitsOfInterest := ctx.Arg(1)
		ServiceBits := ctx.Arg(2)
		_ = ServerName
		_ = ServiceBitsOfInterest
		_ = ServiceBits
		ravelog.Logf("[netapi32] NetLogonSetServiceBits ServerName=0x%x ServiceBitsOfInterest=0x%x ServiceBits=0x%x\n", ServerName, ServiceBitsOfInterest, ServiceBits)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetMessageBufferSend", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		msgname := ctx.Arg(1)
		fromname := ctx.Arg(2)
		buf := ctx.Arg(3)
		buflen := ctx.Arg(4)
		_ = servername
		_ = msgname
		_ = fromname
		_ = buf
		_ = buflen
		ravelog.Logf("[netapi32] NetMessageBufferSend servername=0x%x msgname=0x%x fromname=0x%x buf=0x%x buflen=0x%x\n", servername, msgname, fromname, buf, buflen)
		// NERR_NameNotFound
		ctx.SetReturn(2252)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetMessageNameAdd", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		msgname := ctx.Arg(1)
		_ = servername
		_ = msgname
		ravelog.Logf("[netapi32] NetMessageNameAdd servername=0x%x msgname=0x%x\n", servername, msgname)
		// NERR_NameNotFound
		ctx.SetReturn(2252)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetMessageNameDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		msgname := ctx.Arg(1)
		_ = servername
		_ = msgname
		ravelog.Logf("[netapi32] NetMessageNameDel servername=0x%x msgname=0x%x\n", servername, msgname)
		// NERR_NameNotFound
		ctx.SetReturn(2252)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetMessageNameEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetMessageNameEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetMessageNameGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		msgname := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = servername
		_ = msgname
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetMessageNameGetInfo servername=0x%x msgname=0x%x level=0x%x bufptr=0x%x\n", servername, msgname, level, bufptr)
		// NERR_NameNotFound
		ctx.SetReturn(2252)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetQueryDisplayInformation", func(ctx *ntapi.TrapContext) uint32 {
		ServerName := ctx.Arg(0)
		Level := ctx.Arg(1)
		Index := ctx.Arg(2)
		EntriesRequested := ctx.Arg(3)
		PreferredMaximumLength := ctx.Arg(4)
		ReturnedEntryCount := ctx.Arg(5)
		_ = ServerName
		_ = Level
		_ = Index
		_ = EntriesRequested
		_ = PreferredMaximumLength
		_ = ReturnedEntryCount
		ravelog.Logf("[netapi32] NetQueryDisplayInformation ServerName=0x%x Level=0x%x Index=0x%x EntriesRequested=0x%x PreferredMaximumLength=0x%x ReturnedEntryCount=0x%x\n", ServerName, Level, Index, EntriesRequested, PreferredMaximumLength, ReturnedEntryCount)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetRegisterDomainNameChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
		hEventHandle := ctx.Arg(0)
		_ = hEventHandle
		ravelog.Logf("[netapi32] NetRegisterDomainNameChangeNotification hEventHandle=0x%x\n", hEventHandle)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetRemoteTOD", func(ctx *ntapi.TrapContext) uint32 {
		UncServerName := ctx.Arg(0)
		BufferPtr := ctx.Arg(1)
		_ = UncServerName
		_ = BufferPtr
		ravelog.Logf("[netapi32] NetRemoteTOD UncServerName=0x%x BufferPtr=0x%x\n", UncServerName, BufferPtr)
		// NERR_InvalidComputer
		ctx.SetReturn(2351)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetRemoveAlternateComputerName", func(ctx *ntapi.TrapContext) uint32 {
		Server := ctx.Arg(0)
		AlternateName := ctx.Arg(1)
		DomainAccount := ctx.Arg(2)
		DomainAccountPassword := ctx.Arg(3)
		Reserved := ctx.Arg(4)
		_ = Server
		_ = AlternateName
		_ = DomainAccount
		_ = DomainAccountPassword
		_ = Reserved
		ravelog.Logf("[netapi32] NetRemoveAlternateComputerName Server=0x%x AlternateName=0x%x DomainAccount=0x%x DomainAccountPassword=0x%x Reserved=0x%x\n", Server, AlternateName, DomainAccount, DomainAccountPassword, Reserved)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetRenameMachineInDomain", func(ctx *ntapi.TrapContext) uint32 {
		lpServer := ctx.Arg(0)
		lpNewMachineName := ctx.Arg(1)
		lpAccount := ctx.Arg(2)
		lpPassword := ctx.Arg(3)
		RenameOptions := ctx.Arg(4)
		_ = lpServer
		_ = lpNewMachineName
		_ = lpAccount
		_ = lpPassword
		_ = RenameOptions
		ravelog.Logf("[netapi32] NetRenameMachineInDomain lpServer=0x%x lpNewMachineName=0x%x lpAccount=0x%x lpPassword=0x%x RenameOptions=0x%x\n", lpServer, lpNewMachineName, lpAccount, lpPassword, RenameOptions)
		// ERROR_NO_SUCH_DOMAIN
		ctx.SetReturn(1355)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplExportDirAdd", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetReplExportDirAdd servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplExportDirDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		dirname := ctx.Arg(1)
		_ = servername
		_ = dirname
		ravelog.Logf("[netapi32] NetReplExportDirDel servername=0x%x dirname=0x%x\n", servername, dirname)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplExportDirEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetReplExportDirEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplExportDirGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		dirname := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = servername
		_ = dirname
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetReplExportDirGetInfo servername=0x%x dirname=0x%x level=0x%x bufptr=0x%x\n", servername, dirname, level, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplExportDirLock", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		dirname := ctx.Arg(1)
		_ = servername
		_ = dirname
		ravelog.Logf("[netapi32] NetReplExportDirLock servername=0x%x dirname=0x%x\n", servername, dirname)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplExportDirSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		dirname := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		parm_err := ctx.Arg(4)
		_ = servername
		_ = dirname
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetReplExportDirSetInfo servername=0x%x dirname=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, dirname, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplExportDirUnlock", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		dirname := ctx.Arg(1)
		unlockflags := ctx.Arg(2)
		_ = servername
		_ = dirname
		_ = unlockflags
		ravelog.Logf("[netapi32] NetReplExportDirUnlock servername=0x%x dirname=0x%x unlockflags=0x%x\n", servername, dirname, unlockflags)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = servername
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetReplGetInfo servername=0x%x level=0x%x bufptr=0x%x\n", servername, level, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplImportDirAdd", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetReplImportDirAdd servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplImportDirDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		dirname := ctx.Arg(1)
		_ = servername
		_ = dirname
		ravelog.Logf("[netapi32] NetReplImportDirDel servername=0x%x dirname=0x%x\n", servername, dirname)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplImportDirEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetReplImportDirEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplImportDirGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		dirname := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = servername
		_ = dirname
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetReplImportDirGetInfo servername=0x%x dirname=0x%x level=0x%x bufptr=0x%x\n", servername, dirname, level, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplImportDirLock", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		dirname := ctx.Arg(1)
		_ = servername
		_ = dirname
		ravelog.Logf("[netapi32] NetReplImportDirLock servername=0x%x dirname=0x%x\n", servername, dirname)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplImportDirUnlock", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		dirname := ctx.Arg(1)
		unlockflags := ctx.Arg(2)
		_ = servername
		_ = dirname
		_ = unlockflags
		ravelog.Logf("[netapi32] NetReplImportDirUnlock servername=0x%x dirname=0x%x unlockflags=0x%x\n", servername, dirname, unlockflags)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetReplSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetReplSetInfo servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetScheduleJobAdd", func(ctx *ntapi.TrapContext) uint32 {
		Servername := ctx.Arg(0)
		Buffer := ctx.Arg(1)
		JobId := ctx.Arg(2)
		_ = Servername
		_ = Buffer
		_ = JobId
		ravelog.Logf("[netapi32] NetScheduleJobAdd Servername=0x%x Buffer=0x%x JobId=0x%x\n", Servername, Buffer, JobId)
		// NERR_InvalidComputer
		ctx.SetReturn(2351)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetScheduleJobDel", func(ctx *ntapi.TrapContext) uint32 {
		Servername := ctx.Arg(0)
		MinJobId := ctx.Arg(1)
		MaxJobId := ctx.Arg(2)
		_ = Servername
		_ = MinJobId
		_ = MaxJobId
		ravelog.Logf("[netapi32] NetScheduleJobDel Servername=0x%x MinJobId=0x%x MaxJobId=0x%x\n", Servername, MinJobId, MaxJobId)
		// NERR_InvalidComputer
		ctx.SetReturn(2351)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetScheduleJobEnum", func(ctx *ntapi.TrapContext) uint32 {
		Servername := ctx.Arg(0)
		PointerToBuffer := ctx.Arg(1)
		PreferredMaximumLength := ctx.Arg(2)
		EntriesRead := ctx.Arg(3)
		TotalEntries := ctx.Arg(4)
		ResumeHandle := ctx.Arg(5)
		_ = Servername
		_ = PointerToBuffer
		_ = PreferredMaximumLength
		_ = EntriesRead
		_ = TotalEntries
		_ = ResumeHandle
		ravelog.Logf("[netapi32] NetScheduleJobEnum Servername=0x%x PointerToBuffer=0x%x PreferredMaximumLength=0x%x EntriesRead=0x%x TotalEntries=0x%x ResumeHandle=0x%x\n", Servername, PointerToBuffer, PreferredMaximumLength, EntriesRead, TotalEntries, ResumeHandle)
		// NERR_InvalidComputer
		ctx.SetReturn(2351)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetScheduleJobGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		Servername := ctx.Arg(0)
		JobId := ctx.Arg(1)
		PointerToBuffer := ctx.Arg(2)
		_ = Servername
		_ = JobId
		_ = PointerToBuffer
		ravelog.Logf("[netapi32] NetScheduleJobGetInfo Servername=0x%x JobId=0x%x PointerToBuffer=0x%x\n", Servername, JobId, PointerToBuffer)
		// NERR_InvalidComputer
		ctx.SetReturn(2351)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServerDiskEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetServerDiskEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServerEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetServerEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServerEnumEx", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetServerEnumEx servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServerGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = servername
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetServerGetInfo servername=0x%x level=0x%x bufptr=0x%x\n", servername, level, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServerSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		ParmError := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = ParmError
		ravelog.Logf("[netapi32] NetServerSetInfo servername=0x%x level=0x%x buf=0x%x ParmError=0x%x\n", servername, level, buf, ParmError)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServerTransportAdd", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = servername
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetServerTransportAdd servername=0x%x level=0x%x bufptr=0x%x\n", servername, level, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServerTransportAddEx", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = servername
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetServerTransportAddEx servername=0x%x level=0x%x bufptr=0x%x\n", servername, level, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServerTransportDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = servername
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetServerTransportDel servername=0x%x level=0x%x bufptr=0x%x\n", servername, level, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServerTransportEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetServerTransportEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServiceControl", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		service := ctx.Arg(1)
		opcode := ctx.Arg(2)
		arg := ctx.Arg(3)
		bufptr := ctx.Arg(4)
		_ = servername
		_ = service
		_ = opcode
		_ = arg
		_ = bufptr
		ravelog.Logf("[netapi32] NetServiceControl servername=0x%x service=0x%x opcode=0x%x arg=0x%x bufptr=0x%x\n", servername, service, opcode, arg, bufptr)
		// NERR_ServiceNotInstalled
		ctx.SetReturn(2184)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServiceEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetServiceEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServiceGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		service := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = servername
		_ = service
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetServiceGetInfo servername=0x%x service=0x%x level=0x%x bufptr=0x%x\n", servername, service, level, bufptr)
		// NERR_ServiceNotInstalled
		ctx.SetReturn(2184)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetServiceInstall", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		service := ctx.Arg(1)
		argc := ctx.Arg(2)
		argv := ctx.Arg(3)
		bufptr := ctx.Arg(4)
		_ = servername
		_ = service
		_ = argc
		_ = argv
		_ = bufptr
		ravelog.Logf("[netapi32] NetServiceInstall servername=0x%x service=0x%x argc=0x%x argv=0x%x bufptr=0x%x\n", servername, service, argc, argv, bufptr)
		// NERR_ServiceNotInstalled
		ctx.SetReturn(2184)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetSessionDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		UncClientName := ctx.Arg(1)
		username := ctx.Arg(2)
		_ = servername
		_ = UncClientName
		_ = username
		ravelog.Logf("[netapi32] NetSessionDel servername=0x%x UncClientName=0x%x username=0x%x\n", servername, UncClientName, username)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetSessionEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		UncClientName := ctx.Arg(1)
		username := ctx.Arg(2)
		level := ctx.Arg(3)
		bufptr := ctx.Arg(4)
		prefmaxlen := ctx.Arg(5)
		_ = servername
		_ = UncClientName
		_ = username
		_ = level
		_ = bufptr
		_ = prefmaxlen
		ravelog.Logf("[netapi32] NetSessionEnum servername=0x%x UncClientName=0x%x username=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x\n", servername, UncClientName, username, level, bufptr, prefmaxlen)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetSessionGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		UncClientName := ctx.Arg(1)
		username := ctx.Arg(2)
		level := ctx.Arg(3)
		bufptr := ctx.Arg(4)
		_ = servername
		_ = UncClientName
		_ = username
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetSessionGetInfo servername=0x%x UncClientName=0x%x username=0x%x level=0x%x bufptr=0x%x\n", servername, UncClientName, username, level, bufptr)
		// NERR_ClientNameNotFound
		ctx.SetReturn(2312)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetSetPrimaryComputerName", func(ctx *ntapi.TrapContext) uint32 {
		Server := ctx.Arg(0)
		PrimaryName := ctx.Arg(1)
		DomainAccount := ctx.Arg(2)
		DomainAccountPassword := ctx.Arg(3)
		Reserved := ctx.Arg(4)
		_ = Server
		_ = PrimaryName
		_ = DomainAccount
		_ = DomainAccountPassword
		_ = Reserved
		ravelog.Logf("[netapi32] NetSetPrimaryComputerName Server=0x%x PrimaryName=0x%x DomainAccount=0x%x DomainAccountPassword=0x%x Reserved=0x%x\n", Server, PrimaryName, DomainAccount, DomainAccountPassword, Reserved)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetShareAdd", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetShareAdd servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetShareCheck", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		device := ctx.Arg(1)
		msgType := ctx.Arg(2)
		_ = servername
		_ = device
		_ = msgType
		ravelog.Logf("[netapi32] NetShareCheck servername=0x%x device=0x%x msgType=0x%x\n", servername, device, msgType)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetShareDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		netname := ctx.Arg(1)
		reserved := ctx.Arg(2)
		_ = servername
		_ = netname
		_ = reserved
		ravelog.Logf("[netapi32] NetShareDel servername=0x%x netname=0x%x reserved=0x%x\n", servername, netname, reserved)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetShareDelSticky", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		netname := ctx.Arg(1)
		reserved := ctx.Arg(2)
		_ = servername
		_ = netname
		_ = reserved
		ravelog.Logf("[netapi32] NetShareDelSticky servername=0x%x netname=0x%x reserved=0x%x\n", servername, netname, reserved)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetShareEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetShareEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetShareEnumSticky", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetShareEnumSticky servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetShareGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		netname := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = servername
		_ = netname
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetShareGetInfo servername=0x%x netname=0x%x level=0x%x bufptr=0x%x\n", servername, netname, level, bufptr)
		// NERR_NetNameNotFound
		ctx.SetReturn(2310)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetShareSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		netname := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		parm_err := ctx.Arg(4)
		_ = servername
		_ = netname
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetShareSetInfo servername=0x%x netname=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, netname, level, buf, parm_err)
		// NERR_NetNameNotFound
		ctx.SetReturn(2310)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetStatisticsGet", func(ctx *ntapi.TrapContext) uint32 {
		server := ctx.Arg(0)
		service := ctx.Arg(1)
		level := ctx.Arg(2)
		options := ctx.Arg(3)
		bufptr := ctx.Arg(4)
		_ = server
		_ = service
		_ = level
		_ = options
		_ = bufptr
		ravelog.Logf("[netapi32] NetStatisticsGet server=0x%x service=0x%x level=0x%x options=0x%x bufptr=0x%x\n", server, service, level, options, bufptr)
		// NERR_InvalidComputer
		ctx.SetReturn(2351)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUnjoinDomain", func(ctx *ntapi.TrapContext) uint32 {
		lpServer := ctx.Arg(0)
		lpAccount := ctx.Arg(1)
		lpPassword := ctx.Arg(2)
		fUnjoinOptions := ctx.Arg(3)
		_ = lpServer
		_ = lpAccount
		_ = lpPassword
		_ = fUnjoinOptions
		ravelog.Logf("[netapi32] NetUnjoinDomain lpServer=0x%x lpAccount=0x%x lpPassword=0x%x fUnjoinOptions=0x%x\n", lpServer, lpAccount, lpPassword, fUnjoinOptions)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUnregisterDomainNameChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
		hEventHandle := ctx.Arg(0)
		_ = hEventHandle
		ravelog.Logf("[netapi32] NetUnregisterDomainNameChangeNotification hEventHandle=0x%x\n", hEventHandle)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUseAdd", func(ctx *ntapi.TrapContext) uint32 {
		UncServerName := ctx.Arg(0)
		Level := ctx.Arg(1)
		Buf := ctx.Arg(2)
		ParmError := ctx.Arg(3)
		_ = UncServerName
		_ = Level
		_ = Buf
		_ = ParmError
		ravelog.Logf("[netapi32] NetUseAdd UncServerName=0x%x Level=0x%x Buf=0x%x ParmError=0x%x\n", UncServerName, Level, Buf, ParmError)
		// NERR_UseNotFound
		ctx.SetReturn(2118)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUseDel", func(ctx *ntapi.TrapContext) uint32 {
		UncServerName := ctx.Arg(0)
		UseName := ctx.Arg(1)
		ForceCond := ctx.Arg(2)
		_ = UncServerName
		_ = UseName
		_ = ForceCond
		ravelog.Logf("[netapi32] NetUseDel UncServerName=0x%x UseName=0x%x ForceCond=0x%x\n", UncServerName, UseName, ForceCond)
		// NERR_UseNotFound
		ctx.SetReturn(2118)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUseEnum", func(ctx *ntapi.TrapContext) uint32 {
		UncServerName := ctx.Arg(0)
		Level := ctx.Arg(1)
		BufPtr := ctx.Arg(2)
		PreferedMaximumSize := ctx.Arg(3)
		EntriesRead := ctx.Arg(4)
		TotalEntries := ctx.Arg(5)
		_ = UncServerName
		_ = Level
		_ = BufPtr
		_ = PreferedMaximumSize
		_ = EntriesRead
		_ = TotalEntries
		ravelog.Logf("[netapi32] NetUseEnum UncServerName=0x%x Level=0x%x BufPtr=0x%x PreferedMaximumSize=0x%x EntriesRead=0x%x TotalEntries=0x%x\n", UncServerName, Level, BufPtr, PreferedMaximumSize, EntriesRead, TotalEntries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUseGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		UncServerName := ctx.Arg(0)
		UseName := ctx.Arg(1)
		Level := ctx.Arg(2)
		BufPtr := ctx.Arg(3)
		_ = UncServerName
		_ = UseName
		_ = Level
		_ = BufPtr
		ravelog.Logf("[netapi32] NetUseGetInfo UncServerName=0x%x UseName=0x%x Level=0x%x BufPtr=0x%x\n", UncServerName, UseName, Level, BufPtr)
		// NERR_UseNotFound
		ctx.SetReturn(2118)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserAdd", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetUserAdd servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserChangePassword", func(ctx *ntapi.TrapContext) uint32 {
		domainname := ctx.Arg(0)
		username := ctx.Arg(1)
		oldpassword := ctx.Arg(2)
		newpassword := ctx.Arg(3)
		_ = domainname
		_ = username
		_ = oldpassword
		_ = newpassword
		ravelog.Logf("[netapi32] NetUserChangePassword domainname=0x%x username=0x%x oldpassword=0x%x newpassword=0x%x\n", domainname, username, oldpassword, newpassword)
		// NERR_UserNotFound
		ctx.SetReturn(2221)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		username := ctx.Arg(1)
		_ = servername
		_ = username
		ravelog.Logf("[netapi32] NetUserDel servername=0x%x username=0x%x\n", servername, username)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		filter := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		prefmaxlen := ctx.Arg(4)
		entriesread := ctx.Arg(5)
		_ = servername
		_ = level
		_ = filter
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		ravelog.Logf("[netapi32] NetUserEnum servername=0x%x level=0x%x filter=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x\n", servername, level, filter, bufptr, prefmaxlen, entriesread)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserGetGroups", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		username := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		prefmaxlen := ctx.Arg(4)
		entriesread := ctx.Arg(5)
		_ = servername
		_ = username
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		ravelog.Logf("[netapi32] NetUserGetGroups servername=0x%x username=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x\n", servername, username, level, bufptr, prefmaxlen, entriesread)
		// NERR_UserNotFound
		ctx.SetReturn(2221)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		username := ctx.Arg(1)
		level := ctx.Arg(2)
		bufptr := ctx.Arg(3)
		_ = servername
		_ = username
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetUserGetInfo servername=0x%x username=0x%x level=0x%x bufptr=0x%x\n", servername, username, level, bufptr)
		// NERR_UserNotFound
		ctx.SetReturn(2221)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserGetLocalGroups", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		username := ctx.Arg(1)
		level := ctx.Arg(2)
		flags := ctx.Arg(3)
		bufptr := ctx.Arg(4)
		prefmaxlen := ctx.Arg(5)
		_ = servername
		_ = username
		_ = level
		_ = flags
		_ = bufptr
		_ = prefmaxlen
		ravelog.Logf("[netapi32] NetUserGetLocalGroups servername=0x%x username=0x%x level=0x%x flags=0x%x bufptr=0x%x prefmaxlen=0x%x\n", servername, username, level, flags, bufptr, prefmaxlen)
		// NERR_UserNotFound
		ctx.SetReturn(2221)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserModalsGet", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = servername
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetUserModalsGet servername=0x%x level=0x%x bufptr=0x%x\n", servername, level, bufptr)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserModalsSet", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetUserModalsSet servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserSetGroups", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		username := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		num_entries := ctx.Arg(4)
		_ = servername
		_ = username
		_ = level
		_ = buf
		_ = num_entries
		ravelog.Logf("[netapi32] NetUserSetGroups servername=0x%x username=0x%x level=0x%x buf=0x%x num_entries=0x%x\n", servername, username, level, buf, num_entries)
		// NERR_UserNotFound
		ctx.SetReturn(2221)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetUserSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		username := ctx.Arg(1)
		level := ctx.Arg(2)
		buf := ctx.Arg(3)
		parm_err := ctx.Arg(4)
		_ = servername
		_ = username
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetUserSetInfo servername=0x%x username=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, username, level, buf, parm_err)
		// NERR_UserNotFound
		ctx.SetReturn(2221)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetValidateName", func(ctx *ntapi.TrapContext) uint32 {
		lpServer := ctx.Arg(0)
		lpName := ctx.Arg(1)
		lpAccount := ctx.Arg(2)
		lpPassword := ctx.Arg(3)
		NameType := ctx.Arg(4)
		_ = lpServer
		_ = lpName
		_ = lpAccount
		_ = lpPassword
		_ = NameType
		ravelog.Logf("[netapi32] NetValidateName lpServer=0x%x lpName=0x%x lpAccount=0x%x lpPassword=0x%x NameType=0x%x\n", lpServer, lpName, lpAccount, lpPassword, NameType)
		// ERROR_SUCCESS
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetWkstaGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = servername
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetWkstaGetInfo servername=0x%x level=0x%x bufptr=0x%x\n", servername, level, bufptr)
		// NERR_InvalidComputer
		ctx.SetReturn(2351)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetWkstaSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetWkstaSetInfo servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_InvalidComputer
		ctx.SetReturn(2351)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetWkstaTransportAdd", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = servername
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetWkstaTransportAdd servername=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", servername, level, buf, parm_err)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetWkstaTransportDel", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		transportname := ctx.Arg(1)
		ucond := ctx.Arg(2)
		_ = servername
		_ = transportname
		_ = ucond
		ravelog.Logf("[netapi32] NetWkstaTransportDel servername=0x%x transportname=0x%x ucond=0x%x\n", servername, transportname, ucond)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetWkstaTransportEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetWkstaTransportEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetWkstaUserEnum", func(ctx *ntapi.TrapContext) uint32 {
		servername := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		prefmaxlen := ctx.Arg(3)
		entriesread := ctx.Arg(4)
		totalentries := ctx.Arg(5)
		_ = servername
		_ = level
		_ = bufptr
		_ = prefmaxlen
		_ = entriesread
		_ = totalentries
		ravelog.Logf("[netapi32] NetWkstaUserEnum servername=0x%x level=0x%x bufptr=0x%x prefmaxlen=0x%x entriesread=0x%x totalentries=0x%x\n", servername, level, bufptr, prefmaxlen, entriesread, totalentries)
		// NERR_Success/empty
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetWkstaUserGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		reserved := ctx.Arg(0)
		level := ctx.Arg(1)
		bufptr := ctx.Arg(2)
		_ = reserved
		_ = level
		_ = bufptr
		ravelog.Logf("[netapi32] NetWkstaUserGetInfo reserved=0x%x level=0x%x bufptr=0x%x\n", reserved, level, bufptr)
		// NERR_UserNotFound
		ctx.SetReturn(2221)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetWkstaUserSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		reserved := ctx.Arg(0)
		level := ctx.Arg(1)
		buf := ctx.Arg(2)
		parm_err := ctx.Arg(3)
		_ = reserved
		_ = level
		_ = buf
		_ = parm_err
		ravelog.Logf("[netapi32] NetWkstaUserSetInfo reserved=0x%x level=0x%x buf=0x%x parm_err=0x%x\n", reserved, level, buf, parm_err)
		// NERR_UserNotFound
		ctx.SetReturn(2221)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetapipBufferAllocate", func(ctx *ntapi.TrapContext) uint32 {
		ByteCount := ctx.Arg(0)
		Buffer := ctx.Arg(1)
		_ = ByteCount
		_ = Buffer
		ravelog.Logf("[netapi32] NetapipBufferAllocate ByteCount=0x%x Buffer=0x%x\n", ByteCount, Buffer)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "Netbios", func(ctx *ntapi.TrapContext) uint32 {
		pncb := ctx.Arg(0)
		_ = pncb
		ravelog.Logf("[netapi32] Netbios pncb=0x%x\n", pncb)
		// NRC_GOODRET
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetpAllocStrFromWStr", func(ctx *ntapi.TrapContext) uint32 {
		WStr := ctx.Arg(0)
		_ = WStr
		ravelog.Logf("[netapi32] NetpAllocStrFromWStr WStr=0x%x\n", WStr)
		// NULL/fail
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetpAllocWStrFromStr", func(ctx *ntapi.TrapContext) uint32 {
		AStr := ctx.Arg(0)
		_ = AStr
		ravelog.Logf("[netapi32] NetpAllocWStrFromStr AStr=0x%x\n", AStr)
		// NULL/fail
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetpAllocWStrFromWStr", func(ctx *ntapi.TrapContext) uint32 {
		WStr := ctx.Arg(0)
		_ = WStr
		ravelog.Logf("[netapi32] NetpAllocWStrFromWStr WStr=0x%x\n", WStr)
		// NULL/fail
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetpDeleteSecurityObject", func(ctx *ntapi.TrapContext) uint32 {
		ppSecurityDescriptor := ctx.Arg(0)
		_ = ppSecurityDescriptor
		ravelog.Logf("[netapi32] NetpDeleteSecurityObject ppSecurityDescriptor=0x%x\n", ppSecurityDescriptor)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetpGetComputerName", func(ctx *ntapi.TrapContext) uint32 {
		ComputerName := ctx.Arg(0)
		_ = ComputerName
		ravelog.Logf("[netapi32] NetpGetComputerName ComputerName=0x%x\n", ComputerName)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetpInitOemString", func(ctx *ntapi.TrapContext) uint32 {
		DestinationString := ctx.Arg(0)
		SourceString := ctx.Arg(1)
		_ = DestinationString
		_ = SourceString
		ravelog.Logf("[netapi32] NetpInitOemString DestinationString=0x%x SourceString=0x%x\n", DestinationString, SourceString)
		// void/0
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetpNetBiosStatusToApiStatus", func(ctx *ntapi.TrapContext) uint32 {
		NcbStatus := ctx.Arg(0)
		_ = NcbStatus
		ravelog.Logf("[netapi32] NetpNetBiosStatusToApiStatus NcbStatus=0x%x\n", NcbStatus)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NetpNtStatusToApiStatus", func(ctx *ntapi.TrapContext) uint32 {
		NtStatus := ctx.Arg(0)
		_ = NtStatus
		ravelog.Logf("[netapi32] NetpNtStatusToApiStatus NtStatus=0x%x\n", NtStatus)
		// NERR_Success
		ctx.SetReturn(0)
		return 0
	})
}
