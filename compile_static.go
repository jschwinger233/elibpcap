//go:build static
// +build static

package elibpcap

/*
#cgo CFLAGS: -I$${SRCDIR}/libpcap
#cgo LDFLAGS: -L${SRCDIR}/libpcap -lpcap -static
#include <stdlib.h>
#include <pcap.h>
*/
import "C"
