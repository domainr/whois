package whois_test

import (
	"fmt"
	"testing"

	"github.com/domainr/whois"
	"github.com/nbio/st"
)

func TestParseStatusString(t *testing.T) {
	for status := whois.StatusAddPeriod; status <= whois.StatusUnknown; status = status << 1 {
		str := status.String()
		if str == "" {
			t.Errorf("unexpected empty String() output of Status(%d)", status)
			continue
		}
		st.Expect(t, whois.ParseStatusString(str), status)
	}
}

func TestStatus_String(t *testing.T) {

	tests := []struct {
		status whois.Status
		str    string
	}{
		{
			status: 0,
			str:    "empty",
		},
		{
			status: whois.StatusAddPeriod,
			str:    "addPeriod",
		},
		{
			status: whois.StatusAddPeriod |
				whois.StatusUnknown,
			str: "addPeriod|unknown",
		},
		{
			status: whois.StatusAddPeriod |
				whois.StatusOK |
				whois.StatusUnknown,
			str: "addPeriod|ok|unknown",
		},
		{
			status: whois.StatusAddPeriod |
				whois.StatusAutoRenewPeriod |
				whois.StatusInactive |
				whois.StatusOK |
				whois.StatusPendingCreate |
				whois.StatusPendingDelete |
				whois.StatusPendingRenew |
				whois.StatusPendingRestore |
				whois.StatusPendingTransfer |
				whois.StatusPendingUpdate |
				whois.StatusRedemptionPeriod |
				whois.StatusRenewPeriod |
				whois.StatusServerDeleteProhibited |
				whois.StatusServerHold |
				whois.StatusServerRenewProhibited |
				whois.StatusServerTransferProhibited |
				whois.StatusServerUpdateProhibited |
				whois.StatusTransferPeriod |
				whois.StatusClientDeleteProhibited |
				whois.StatusClientHold |
				whois.StatusClientRenewProhibited |
				whois.StatusClientTransferProhibited |
				whois.StatusClientUpdateProhibited |
				whois.StatusUnknown,
			str: "addPeriod|autoRenewPeriod|inactive|ok|pendingCreate|pendingDelete|pendingRenew|pendingRestore|pendingTransfer|pendingUpdate|redemptionPeriod|renewPeriod|serverDeleteProhibited|serverHold|serverRenewProhibited|serverTransferProhibited|serverUpdateProhibited|transferPeriod|clientDeleteProhibited|clientHold|clientRenewProhibited|clientTransferProhibited|clientUpdateProhibited|unknown",
		},
	}

	for i, test := range tests {
		// combined status string
		st.Expect(t, test.status.String(), test.str, i)
	}
}

func TestStatus_GoString(t *testing.T) {
	for status := whois.StatusAddPeriod; status <= whois.StatusUnknown; status = status << 1 {
		str, gostr := status.String(), status.GoString()
		if str == "" {
			t.Errorf("unexpected empty String() output of Status(%d)", status)
			continue
		}
		st.Expect(t, fmt.Sprintf("whois.Status(%s)", str), gostr)
	}
}

func TestDNSSECState(t *testing.T) {

	// test on String()
	st.Expect(t, whois.DNSSECSignedDelegation.String(), "signedDelegation")
	st.Expect(t, whois.DNSSECUnsigned.String(), "unsigned")
	st.Expect(t, whois.DNSSECState(0).String(), "invalid")
	st.Expect(t, (whois.DNSSECUnsigned + 1).String(), "invalid")

	// test on GoString()
	st.Expect(t, whois.DNSSECSignedDelegation.GoString(), "whois.DNSSECState(signedDelegation)")
	st.Expect(t, whois.DNSSECUnsigned.GoString(), "whois.DNSSECState(unsigned)")

	// test on ParseDNSSECState()
	st.Expect(t, whois.ParseDNSSECState("signedDelegation").String(), "signedDelegation")
	st.Expect(t, whois.ParseDNSSECState("unsigned").String(), "unsigned")
}
