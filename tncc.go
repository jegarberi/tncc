package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Packet encoding/decoding helpers (mirrors Python script)

func encodePacket(cmd uint32, align int, payload []byte) []byte {
	buf := make([]byte, 0, 12+len(payload)+4)
	// alignment padding for body (not header)
	if align > 1 {
		pad := (align - ((len(payload) + 12) % align)) % align
		if pad > 0 {
			payload = append(payload, make([]byte, pad)...)
		}
	}
	length := uint16(len(payload) + 12)

	head := make([]byte, 12)
	binary.BigEndian.PutUint32(head[0:4], cmd)
	head[4] = 0xc0
	head[5] = 0x00
	binary.BigEndian.PutUint16(head[6:8], length)
	binary.BigEndian.PutUint32(head[8:12], 0x0000583)

	buf = append(buf, head...)
	buf = append(buf, payload...)
	return buf
}

func encode0013(payload []byte) []byte { return encodePacket(0x0013, 4, payload) }
func encode0ce4(payload []byte) []byte { return encodePacket(0x0ce4, 4, payload) }

func encode0ce5(s string) []byte {
	return encodePacket(0x0ce5, 1, []byte(s))
}

func encode0ce7(s string) []byte {
	// ">I" + s + "x" with prefix 0x00058316 and a trailing pad byte
	b := make([]byte, 0, 4+len(s)+1)
	p := make([]byte, 4)
	binary.BigEndian.PutUint32(p, 0x00058316)
	b = append(b, p...)
	b = append(b, []byte(s)...)
	b = append(b, 0x00)
	return encodePacket(0x0ce7, 1, b)
}

// minimal decoder to extract compressed data from the TNCC message

func abbrev(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

type pkt struct {
	cmd    uint32
	length uint16
	data   []byte
}

func decodeOnePacket(buf []byte) (pkt, []byte, error) {
	if len(buf) < 12 {
		return pkt{}, nil, errors.New("buffer too short for header")
	}
	p := pkt{}
	p.cmd = binary.BigEndian.Uint32(buf[0:4])
	p.length = binary.BigEndian.Uint16(buf[6:8])
	if int(p.length) < 12 || int(p.length) > len(buf) {
		return pkt{}, nil, errors.New("invalid length in packet")
	}
	p.data = make([]byte, int(p.length)-12)
	copy(p.data, buf[12:int(p.length)])
	return p, buf[int(p.length):], nil
}

// extractCompressedFromMsg replicates get_msg_contents in Python
func extractCompressedFromMsg(msgB64 string) ([]byte, error) {
	logf("extractCompressedFromMsg b64_len=%d", len(msgB64))
	raw, err := base64.StdEncoding.DecodeString(msgB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	logf("decoded msg bytes=%d", len(raw))
	// first level should be 0x0013 which contains nested packets
	p, rest, err := decodeOnePacket(raw)
	if err != nil {
		return nil, err
	}
	logf("outer packet cmd=0x%x len=%d rest=%d", p.cmd, p.length, len(rest))
	if p.cmd != 0x0013 {
		return nil, fmt.Errorf("unexpected cmd 0x%x, want 0x0013", p.cmd)
	}
	// inside p.data, there are more packets; look for 0x0ce4
	var ce4 []byte
	buf := p.data
	for len(buf) >= 12 {
		ip, r, err := decodeOnePacket(buf)
		if err != nil {
			break
		}
		logf("inner packet cmd=0x%x len=%d", ip.cmd, ip.length)
		if ip.cmd == 0x0ce4 {
			ce4 = ip.data
			break
		}
		buf = r
	}
	if ce4 == nil {
		return nil, errors.New("0x0ce4 not found in msg")
	}
	logf("found 0x0ce4 block len=%d", len(ce4))
	// inside ce4, again nested packets; we need 0x0ce7
	buf = ce4
	var ce7 []byte
	for len(buf) >= 12 {
		ip, r, err := decodeOnePacket(buf)
		if err != nil {
			break
		}
		logf("0x0ce4 child cmd=0x%x len=%d", ip.cmd, ip.length)
		if ip.cmd == 0x0ce7 {
			ce7 = ip.data
			break
		}
		buf = r
	}
	if ce7 == nil {
		return nil, errors.New("0x0ce7 not found in 0x0ce4")
	}
	logf("found 0x0ce7 len=%d", len(ce7))
	// 0x0ce7 data starts with 4-byte prefix, then a string (may have a pad byte at end)
	if len(ce7) < 4 {
		return nil, errors.New("0x0ce7 too short")
	}
	payload := ce7[4:]
	// Split by first two ':' occurrences
	parts := bytes.SplitN(payload, []byte{':'}, 3)
	if len(parts) < 3 {
		return nil, errors.New("compressed payload format invalid")
	}
	logf("payload typ=%s lenField=%s data_len=%d", string(parts[0]), string(parts[1]), len(parts[2]))
	data := parts[2]
	// zlib-decompress
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zlib reader: %w", err)
	}
	defer zr.Close()
	var out bytes.Buffer
	if _, err := io.Copy(&out, zr); err != nil {
		return nil, fmt.Errorf("zlib copy: %w", err)
	}
	logf("decompressed bytes=%d", out.Len())
	return out.Bytes(), nil
}

// HTML-ish parser: collect value="..." and parse semicolon-separated key=value pairs
var valueAttrRE = regexp.MustCompile(`(?i)value="([^"]*)"`)

func parseMsgHTMLish(b []byte) []map[string]string {
	matches := valueAttrRE.FindAllSubmatch(b, -1)
	var objs []map[string]string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		val := string(m[1])
		mapp := map[string]string{}
		parts := strings.Split(val, ";")
		for _, f := range parts {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			kv := strings.SplitN(f, "=", 2)
			if len(kv) == 2 {
				mapp[kv[0]] = kv[1]
			}
		}
		objs = append(objs, mapp)
	}
	return objs
}

// Simple stdout logger with timestamp + file:function:line
func logf(format string, a ...interface{}) {
	ts := time.Now().Format(time.RFC3339)
	pc, file, line, ok := runtime.Caller(1)
	fn := "?"
	if ok {
		if f := runtime.FuncForPC(pc); f != nil {
			fn = f.Name()
		}
		file = filepath.Base(file)
	} else {
		file = "?"
		line = 0
	}
	fmt.Printf("%s %s:%d %s "+format+"\n", append([]any{ts, file, line, fn}, a...)...)
}

// Helpers to log raw data sent/received
func logData(direction, channel string, b []byte) {
	logf("%s %s bytes=%d TEXT:%s", direction, channel, len(b), string(b))
	logf("%s %s HEX:%s", direction, channel, hex.EncodeToString(b))
}

func dumpHeaders(prefix string, h http.Header) {
	for k, vals := range h {
		for _, v := range vals {
			logf("%s %s: %s", prefix, k, v)
		}
	}
}

// TNCC client

type TNCC struct {
	vpnHost   string
	path      string
	client    *http.Client
	userAgent string
}

func newTNCC(vpnHost string) *TNCC {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cl := &http.Client{Transport: tr, Jar: jar, Timeout: 30 * time.Second}
	return &TNCC{
		vpnHost:   vpnHost,
		path:      "/dana-na/",
		client:    cl,
		userAgent: "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1",
	}
}

func (t *TNCC) baseURL() string { return "https://" + t.vpnHost }

func (t *TNCC) setCookie(name, value string) error {
	u, _ := url.Parse(t.baseURL())
	c := &http.Cookie{
		Name:   name,
		Value:  value,
		Domain: t.vpnHost,
		Path:   t.path,
		Secure: true,
	}
	logf("setCookie %s=%s (domain=%s path=%s)", name, value, c.Domain, c.Path)
	t.client.Jar.SetCookies(u, append(t.client.Jar.Cookies(u), c))
	return nil
}

func (t *TNCC) findCookie(name string) *http.Cookie {
	u, _ := url.Parse(t.baseURL())
	// Try base URL first
	for _, c := range t.client.Jar.Cookies(u) {
		logf("findCookie %s=%s (domain=%s path=%s)", c.Name, c.Value, c.Domain, c.Path)
		if c.Name == name {
			return c
		}
	}
	// Try with /dana-na/ path as well (in case cookie path differs)
	u2, _ := url.Parse(t.baseURL() + t.path)
	for _, c := range t.client.Jar.Cookies(u2) {
		logf("findCookie(dana-na) %s=%s (domain=%s path=%s)", c.Name, c.Value, c.Domain, c.Path)
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (t *TNCC) parseResponse(body []byte) map[string]string {
	logf("parseResponse body_len=%d", len(body))
	resp := map[string]string{}
	s := bufio.NewScanner(bytes.NewReader(body))
	s.Split(bufio.ScanLines)
	lastKey := ""
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		logf("resp line: %s", line)
		if lastKey == "msg" && len(line) > 0 {
			resp["msg"] += line
			continue
		}
		key := ""
		if i := strings.IndexByte(line, '='); i >= 0 {
			key = line[:i]
			resp[key] = line[i+1:]
			logf("resp kv: %s=<%d bytes>", key, len(resp[key]))
		}
		lastKey = key
	}
	return resp
}

func (t *TNCC) doPostHC(body []byte) ([]byte, error) {
	u := t.baseURL() + t.path + "hc/tnchcupdate.cgi"
	logf("HTTP REQ POST %s body_len=%d", u, len(body))
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", t.userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Log request headers and body
	dumpHeaders("HTTP req hdr", req.Header)
	logf("HTTP req body TEXT:%s", strings.ReplaceAll(string(body), "\n", "\\n"))
	logf("HTTP req body HEX:%s", hex.EncodeToString(body))

	start := time.Now()

	resp, err := t.client.Do(req)
	if err != nil {
		logf("HTTP POST error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logf("HTTP read body error: %v", err)
		return nil, err
	}
	elapsed := time.Since(start)
	logf("HTTP RESP %d %s resp_len=%d dur=%s", resp.StatusCode, resp.Status, len(respBody), elapsed)
	dumpHeaders("HTTP resp hdr", resp.Header)
	logf("HTTP resp body TEXT:%s", strings.ReplaceAll(string(respBody), "\n", "\\n"))
	logf("HTTP resp body HEX:%s", hex.EncodeToString(respBody))
	return respBody, nil
}

func (t *TNCC) GetCookie(dspreauth, dssignin *string) (*http.Cookie, error) {
	logf("GetCookie start dspreauth_provided=%t dssignin_provided=%t", dspreauth != nil && *dspreauth != "", dssignin != nil && *dssignin != "")
	// Mirror Python: if dspreauth or dssignin are not provided, open base URL first
	if (dspreauth == nil || *dspreauth == "") || (dssignin == nil || *dssignin == "") {
		u := t.baseURL()
		logf("HTTP REQ GET %s", u)
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		req.Header.Set("User-Agent", t.userAgent)
		dumpHeaders("HTTP req hdr", req.Header)
		resp, err := t.client.Do(req)
		if err == nil && resp != nil {
			respBody, rerr := io.ReadAll(resp.Body)
			if rerr != nil {
				logf("initial GET read error: %v", rerr)
			} else {
				logf("HTTP RESP %d %s resp_len=%d", resp.StatusCode, resp.Status, len(respBody))
				dumpHeaders("HTTP resp hdr", resp.Header)
				logf("HTTP resp body TEXT:%s", strings.ReplaceAll(string(respBody), "\n", "\\n"))
				logf("HTTP resp body HEX:%s", hex.EncodeToString(respBody))
			}
			resp.Body.Close()
		} else if err != nil {
			logf("initial GET error: %v", err)
		}
	}
	if dspreauth != nil && *dspreauth != "" {
		_ = t.setCookie("DSPREAUTH", *dspreauth)
	}
	if dssignin != nil && *dssignin != "" {
		_ = t.setCookie("DSSIGNIN", *dssignin)
	}
	// Initial policy request
	msgRaw := encode0013(append(encode0ce4(encode0ce7("policy request")), encode0ce5("Accept-Language: en")...))
	logf("built policy request msg_raw_len=%d", len(msgRaw))
	msg := base64.StdEncoding.EncodeToString(msgRaw)
	postData := []byte("connId=0;msg=" + msg + ";firsttime=1;")
	logf("posting initial policy request len=%d", len(postData))
	logf("%s", postData)
	body, err := t.doPostHC(postData)
	if err != nil {
		return nil, err
	}
	respMap := t.parseResponse(body)
	msgField, ok := respMap["msg"]
	if !ok {
		return nil, errors.New("no msg in response")
	}
	logf("got msg field len=%d", len(msgField))
	data, err := extractCompressedFromMsg(msgField)
	if err != nil {
		logf("extractCompressedFromMsg error: %v", err)
		// proceed with empty object list if server returns no data
	}
	objs := []map[string]string{}
	if err == nil && len(data) > 0 {
		objs = parseMsgHTMLish(data)
	}
	logf("parsed objects count=%d", len(objs))
	// Build policy set
	policySet := map[string]struct{}{}
	for _, obj := range objs {
		if p, ok := obj["policy"]; ok {
			policySet[p] = struct{}{}
			logf("policy entry: %s", p)
		}
	}
	policies := make([]string, 0, len(policySet))
	for p := range policySet {
		policies = append(policies, p)
	}
	sort.Strings(policies)
	logf("policies total=%d", len(policies))
	// Build policy_report
	var report strings.Builder
	for _, p := range policies {
		report.WriteString("\npolicy:")
		report.WriteString(p)
		report.WriteString("\nstatus:OK\n")
	}
	msgRaw2 := encode0013(append(encode0ce4(encode0ce7(report.String())), encode0ce5("Accept-Language: en")...))
	msg2 := base64.StdEncoding.EncodeToString(msgRaw2)
	postData2 := []byte("connId=1;msg=" + msg2 + ";firsttime=1;")
	logf("posting policy report len=%d", len(postData2))
	_, err = t.doPostHC(postData2)
	if err != nil {
		return nil, err
	}
	// Return DSPREAUTH cookie

	c := t.findCookie("DSPREAUTH")
	if c == nil {
		return nil, errors.New("DSPREAUTH cookie not found")
	}
	logf("GetCookie success DSPREAUTH=%s", abbrev(c.Value, 24))
	return c, nil
}

// Socket-aware command server compatible with the Python behavior
// If fd 0 is a Unix socket (e.g., SOCK_SEQPACKET), use it; otherwise, fall back to one-shot stdin.
func runServer(t *TNCC) error {
	// Try to treat stdin (fd 0) as a network connection
	if f := os.Stdin; f != nil {
		if conn, err := net.FileConn(f); err == nil {
			defer conn.Close()
			if uc, ok := conn.(*net.UnixConn); ok {
				logf("server: detected Unix socket on stdin")
				return runServerUnix(t, uc)
			}
			logf("server: stdin is a net.Conn but not Unix; using stdin fallback")
		}
	}
	return runServerStdinOnce(t)
}

// Fallback: read a single request from stdin and write response to stdout
func runServerStdinOnce(t *TNCC) error {
	in := bufio.NewReader(os.Stdin)
	logf("waiting for stdin request (fallback)")
	reqBytes, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	logf("server read %d bytes from stdin", len(reqBytes))
	if len(reqBytes) == 0 {
		return nil
	}
	logData("RX", "stdin", reqBytes)
	return handleOneCommand(t, string(reqBytes), func(resp string) error {
		for i := 0; i < 4; i++ {
			b := []byte(resp)
			logData("TX", "stdout", b)
			if _, err := os.Stdout.Write(b); err != nil {
				return err
			}
		}
		return nil
	})
}

// Socket mode: read one datagram/packet at a time and reply on the same socket
func runServerUnix(t *TNCC, uc *net.UnixConn) error {
	buf := make([]byte, 128*1024)
	for {
		_ = uc.SetReadDeadline(time.Now().Add(20 * time.Second))
		n, _, _, _, err := uc.ReadMsgUnix(buf, nil)
		if err != nil {
			// Timeout or closed socket ends the loop (matches Python which exits on no data)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				logf("server socket timeout, exiting")
				return nil
			}
			if errors.Is(err, io.EOF) {
				logf("server socket EOF, exiting")
				return nil
			}
			// Connection reset by peer is a normal termination
			if strings.Contains(err.Error(), "connection reset by peer") {
				logf("server socket connection reset, exiting")
				return nil
			}
			return err
		}
		if n == 0 {
			logf("server socket read 0 bytes, exiting")
			return nil
		}
		logf("server socket received %d bytes", n)
		logData("RX", "socket", buf[:n])
		req := string(buf[:n])
		err = handleOneCommand(t, req, func(resp string) error {
			for i := 0; i < 4; i++ {
				b := []byte(resp)
				logData("TX", "socket", b)
				if _, err := uc.Write(b); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			logf("command handling error: %v", err)
			// For compatibility, continue loop rather than hard fail
		}
	}
}

// Shared command parsing and handling; responder writes the reply
func handleOneCommand(t *TNCC, req string, responder func(resp string) error) error {
	lines := strings.Split(req, "\n")
	if len(lines) == 0 {
		return nil
	}
	cmd := strings.TrimSpace(lines[0])
	logf("server cmd=%s", cmd)
	args := map[string]string{}
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if i := strings.IndexByte(l, '='); i >= 0 {
			key := l[:i]
			val := l[i+1:]
			args[key] = val
		}
	}
	logf("server args keys=%v", func() []string {
		ks := make([]string, 0, len(args))
		for k := range args {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}())
	switch cmd {
	case "start":
		start := time.Now()
		cookie, err := t.GetCookie(ptrOrNil(args["Cookie"]), ptrOrNil(args["DSSIGNIN"]))
		if err != nil {
			logf("GetCookie error: %v", err)
			return err
		}
		resp := fmt.Sprintf("200\n3\n%s\n\n", cookie.Value)
		if err := responder(resp); err != nil {
			return err
		}
		if err := responder(resp); err != nil {
			return err
		}
		if err := responder(resp); err != nil {
			return err
		}
		if err := responder(resp); err != nil {
			return err
		}
		logf("start handled, cookie_len=%d dur=%s", len(cookie.Value), time.Since(start))
	case "setcookie":
		time.Sleep(time.Second)
		logf("setcookie handled")
		// No response required per original behavior
	default:
		logf("unknown cmd: %s", cmd)
	}
	return nil
}

func ptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func main() {
	args := os.Args
	logf("tncc starting args=%v", args)
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tncc <vpn_host> [DSPREAUTH DSSIGNIN]")
		os.Exit(2)
	}
	vpnHost := args[1]
	logf("vpnHost=%s", vpnHost)
	t := newTNCC(vpnHost)
	if len(args) == 4 {
		logf("mode=direct")
		dspre := args[2]
		dss := args[3]
		c, err := t.GetCookie(&dspre, &dss)
		if err != nil {
			logf("direct GetCookie error: %v", err)
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Println(c.Value)
		logf("direct mode done")
		return
	}
	logf("mode=server stdin")
	if err := runServer(t); err != nil {
		logf("server error: %v", err)
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
	logf("server mode done")
}
