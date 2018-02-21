package parser_test

import (
	"fmt"
	"testing"

	parser "github.com/domainr/whois/whois-parser"
	"github.com/nbio/st"
)

func TestParseStatusString(t *testing.T) {
	for status := parser.StatusAddPeriod; status <= parser.StatusUnknown; status = status << 1 {
		str := status.String()
		if str == "" {
			t.Errorf("unexpected empty String() output of Status(%d)", status)
			continue
		}
		st.Expect(t, parser.ParseStatusString(str), status)
	}
	st.Expect(
		t,
		parser.ParseStatusString("clientTransferProhibited https://icann.org/epp#clientTransferProhibited"),
		parser.StatusClientTransferProhibited,
	)
}

func TestStatus_String(t *testing.T) {

	tests := []struct {
		status parser.Status
		str    string
	}{
		{
			status: 0,
			str:    "empty",
		},
		{
			status: parser.StatusAddPeriod,
			str:    "addPeriod",
		},
		{
			status: parser.StatusAddPeriod |
				parser.StatusUnknown,
			str: "addPeriod|unknown",
		},
		{
			status: parser.StatusAddPeriod |
				parser.StatusOK |
				parser.StatusUnknown,
			str: "addPeriod|ok|unknown",
		},
		{
			status: parser.StatusAddPeriod |
				parser.StatusAutoRenewPeriod |
				parser.StatusInactive |
				parser.StatusOK |
				parser.StatusPendingCreate |
				parser.StatusPendingDelete |
				parser.StatusPendingRenew |
				parser.StatusPendingRestore |
				parser.StatusPendingTransfer |
				parser.StatusPendingUpdate |
				parser.StatusRedemptionPeriod |
				parser.StatusRenewPeriod |
				parser.StatusServerDeleteProhibited |
				parser.StatusServerHold |
				parser.StatusServerRenewProhibited |
				parser.StatusServerTransferProhibited |
				parser.StatusServerUpdateProhibited |
				parser.StatusTransferPeriod |
				parser.StatusClientDeleteProhibited |
				parser.StatusClientHold |
				parser.StatusClientRenewProhibited |
				parser.StatusClientTransferProhibited |
				parser.StatusClientUpdateProhibited |
				parser.StatusUnknown,
			str: "addPeriod|autoRenewPeriod|inactive|ok|pendingCreate|pendingDelete|pendingRenew|pendingRestore|pendingTransfer|pendingUpdate|redemptionPeriod|renewPeriod|serverDeleteProhibited|serverHold|serverRenewProhibited|serverTransferProhibited|serverUpdateProhibited|transferPeriod|clientDeleteProhibited|clientHold|clientRenewProhibited|clientTransferProhibited|clientUpdateProhibited|unknown",
		},
	}

	for i, test := range tests {
		// combined status string
		st.Expect(t, test.status.String(), test.str, i)
	}
}

func TestStatus_GoString(t *testing.T) {
	for status := parser.StatusAddPeriod; status <= parser.StatusUnknown; status = status << 1 {
		str, gostr := status.String(), status.GoString()
		if str == "" {
			t.Errorf("unexpected empty String() output of Status(%d)", status)
			continue
		}
		st.Expect(t, fmt.Sprintf("Status(%s)", str), gostr)
	}
}

func TestDNSSECState(t *testing.T) {

	// test on String()
	st.Expect(t, parser.DNSSECSignedDelegation.String(), "signedDelegation")
	st.Expect(t, parser.DNSSECUnsigned.String(), "unsigned")
	st.Expect(t, parser.DNSSECState(0).String(), "invalid")
	st.Expect(t, (parser.DNSSECUnsigned + 1).String(), "invalid")

	// test on GoString()
	st.Expect(t, parser.DNSSECSignedDelegation.GoString(), "DNSSEC(signedDelegation)")
	st.Expect(t, parser.DNSSECUnsigned.GoString(), "DNSSEC(unsigned)")

	// test on ParseDNSSECState()
	st.Expect(t, parser.ParseDNSSECState("signedDelegation").String(), "signedDelegation")
	st.Expect(t, parser.ParseDNSSECState("unsigned").String(), "unsigned")
}
